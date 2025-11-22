// CRITICAL #4: Rate Limiting - Protection for video upload endpoints
import { Request, Response, NextFunction } from "express";

interface RateLimitEntry {
  count: number;
  windowStart: number;
  lastRequest: number;
}

export class VideoUploadRateLimiter {
  private ipLimits = new Map<string, RateLimitEntry>();
  private userLimits = new Map<string, RateLimitEntry>();
  
  // Rate limiting configuration
  private readonly limits = {
    // Per IP address limits
    ip: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxRequests: 50, // Max 50 requests per IP per 15 minutes
      maxConcurrent: 3, // Max 3 concurrent uploads per IP
    },
    // Per user limits  
    user: {
      windowMs: 5 * 60 * 1000, // 5 minutes
      maxRequests: 20, // Max 20 requests per user per 5 minutes
      maxConcurrent: 2, // Max 2 concurrent uploads per user
      maxPayloadMB: 10, // Max 10MB per request
    }
  };

  private concurrentUploads = new Map<string, Set<string>>(); // Track concurrent uploads

  // Clean up expired entries periodically
  constructor() {
    setInterval(() => {
      this.cleanupExpiredEntries();
    }, 5 * 60 * 1000); // Cleanup every 5 minutes
  }

  private cleanupExpiredEntries() {
    const now = Date.now();
    
    // Cleanup IP limits
    Array.from(this.ipLimits.entries()).forEach(([ip, entry]) => {
      if (now - entry.windowStart > this.limits.ip.windowMs) {
        this.ipLimits.delete(ip);
      }
    });

    // Cleanup user limits
    Array.from(this.userLimits.entries()).forEach(([userId, entry]) => {
      if (now - entry.windowStart > this.limits.user.windowMs) {
        this.userLimits.delete(userId);
      }
    });
  }

  private getClientIP(req: Request): string {
    return req.ip || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress || 
           (req.connection as any)?.socket?.remoteAddress || 
           'unknown';
  }

  private updateRateLimit(
    map: Map<string, RateLimitEntry>, 
    key: string, 
    windowMs: number
  ): RateLimitEntry {
    const now = Date.now();
    const entry = map.get(key);
    
    if (!entry || now - entry.windowStart > windowMs) {
      // New window or expired entry
      const newEntry = {
        count: 1,
        windowStart: now,
        lastRequest: now
      };
      map.set(key, newEntry);
      return newEntry;
    }
    
    // Update existing entry
    entry.count++;
    entry.lastRequest = now;
    map.set(key, entry);
    return entry;
  }

  // Middleware for video upload endpoints
  videoUploadLimit = (req: Request, res: Response, next: NextFunction) => {
    const clientIP = this.getClientIP(req);
    const userId = req.user?.id;
    const now = Date.now();

    // Check payload size limit
    const contentLength = parseInt(req.headers['content-length'] || '0');
    if (contentLength > this.limits.user.maxPayloadMB * 1024 * 1024) {
      console.log(`[RATE_LIMIT] Payload too large: ${contentLength} bytes from IP ${clientIP}, user ${userId}`);
      return res.status(413).json({ 
        message: `Размер файла превышает ${this.limits.user.maxPayloadMB}MB`,
        code: 'PAYLOAD_TOO_LARGE'
      });
    }

    // Check IP-based rate limiting
    const ipEntry = this.updateRateLimit(this.ipLimits, clientIP, this.limits.ip.windowMs);
    if (ipEntry.count > this.limits.ip.maxRequests) {
      console.log(`[RATE_LIMIT] IP rate limit exceeded: ${clientIP}, ${ipEntry.count} requests`);
      return res.status(429).json({ 
        message: 'Слишком много запросов с вашего IP. Попробуйте позже.',
        code: 'IP_RATE_LIMIT_EXCEEDED',
        retryAfter: Math.ceil((this.limits.ip.windowMs - (now - ipEntry.windowStart)) / 1000)
      });
    }

    // Check user-based rate limiting (if authenticated)
    if (userId) {
      const userEntry = this.updateRateLimit(this.userLimits, userId, this.limits.user.windowMs);
      if (userEntry.count > this.limits.user.maxRequests) {
        console.log(`[RATE_LIMIT] User rate limit exceeded: ${userId}, ${userEntry.count} requests`);
        return res.status(429).json({ 
          message: 'Превышен лимит загрузок. Попробуйте позже.',
          code: 'USER_RATE_LIMIT_EXCEEDED',
          retryAfter: Math.ceil((this.limits.user.windowMs - (now - userEntry.windowStart)) / 1000)
        });
      }

      // Check concurrent upload limits
      const concurrentKey = `${userId}:${clientIP}`;
      const currentConcurrent = this.concurrentUploads.get(concurrentKey)?.size || 0;
      
      if (currentConcurrent >= this.limits.user.maxConcurrent) {
        console.log(`[RATE_LIMIT] Too many concurrent uploads: ${userId}, ${currentConcurrent} uploads`);
        return res.status(429).json({ 
          message: 'Слишком много одновременных загрузок. Дождитесь завершения текущих.',
          code: 'TOO_MANY_CONCURRENT_UPLOADS',
          currentConcurrent,
          maxConcurrent: this.limits.user.maxConcurrent
        });
      }

      // Track this upload
      const uploadId = `${Date.now()}-${Math.random()}`;
      if (!this.concurrentUploads.has(concurrentKey)) {
        this.concurrentUploads.set(concurrentKey, new Set());
      }
      this.concurrentUploads.get(concurrentKey)!.add(uploadId);

      // Clean up tracking when request completes
      const originalSend = res.send;
      const originalJson = res.json;
      
      const cleanup = () => {
        const uploads = this.concurrentUploads.get(concurrentKey);
        if (uploads) {
          uploads.delete(uploadId);
          if (uploads.size === 0) {
            this.concurrentUploads.delete(concurrentKey);
          }
        }
      };

      res.send = function(body) {
        cleanup();
        return originalSend.call(this, body);
      };

      res.json = function(body) {
        cleanup();
        return originalJson.call(this, body);
      };

      // Also cleanup on connection close/error
      req.on('close', cleanup);
      req.on('error', cleanup);
    }

    console.log(`[RATE_LIMIT] Request allowed: IP ${clientIP}, user ${userId}, IP count: ${ipEntry.count}/${this.limits.ip.maxRequests}`);
    next();
  };

  // Admin endpoint rate limiting - more restrictive
  adminVideoLimit = (req: Request, res: Response, next: NextFunction) => {
    const clientIP = this.getClientIP(req);
    const userId = req.user?.id;
    
    // Admin endpoints have stricter limits
    const adminLimits = {
      windowMs: 10 * 60 * 1000, // 10 minutes
      maxRequests: 30, // Max 30 admin video operations per 10 minutes
    };

    const adminKey = `admin:${userId}:${clientIP}`;
    const entry = this.updateRateLimit(this.userLimits, adminKey, adminLimits.windowMs);
    
    if (entry.count > adminLimits.maxRequests) {
      console.log(`[RATE_LIMIT] Admin rate limit exceeded: ${userId} from ${clientIP}`);
      return res.status(429).json({ 
        message: 'Превышен лимит административных операций.',
        code: 'ADMIN_RATE_LIMIT_EXCEEDED',
        retryAfter: Math.ceil((adminLimits.windowMs - (Date.now() - entry.windowStart)) / 1000)
      });
    }

    console.log(`[RATE_LIMIT] Admin request allowed: ${userId}, count: ${entry.count}/${adminLimits.maxRequests}`);
    next();
  };

  // Get current rate limit status for monitoring
  getRateLimitStatus(ip?: string, userId?: string): { ip?: any, user?: any } {
    const status: any = {};
    
    if (ip && this.ipLimits.has(ip)) {
      const entry = this.ipLimits.get(ip)!;
      status.ip = {
        count: entry.count,
        limit: this.limits.ip.maxRequests,
        windowStart: entry.windowStart,
        lastRequest: entry.lastRequest
      };
    }
    
    if (userId && this.userLimits.has(userId)) {
      const entry = this.userLimits.get(userId)!;
      status.user = {
        count: entry.count,
        limit: this.limits.user.maxRequests,
        windowStart: entry.windowStart,
        lastRequest: entry.lastRequest
      };
    }
    
    return status;
  }

  // Emergency disable for maintenance
  private isEmergencyMode = false;
  
  enableEmergencyMode() {
    this.isEmergencyMode = true;
    console.log('[RATE_LIMIT] Emergency mode enabled - blocking all video uploads');
  }
  
  disableEmergencyMode() {
    this.isEmergencyMode = false;
    console.log('[RATE_LIMIT] Emergency mode disabled');
  }

  // Emergency middleware
  emergencyMode = (req: Request, res: Response, next: NextFunction) => {
    if (this.isEmergencyMode) {
      return res.status(503).json({
        message: 'Сервис временно недоступен. Попробуйте позже.',
        code: 'EMERGENCY_MODE'
      });
    }
    next();
  };
}

// Singleton instance for global use
export const videoUploadRateLimiter = new VideoUploadRateLimiter();