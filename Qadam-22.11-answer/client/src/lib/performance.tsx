import React from 'react';

// Performance utilities for PWA optimization

// Lazy loading utilities
export const createLazyComponent = <T extends React.ComponentType<any>>(
  importFunc: () => Promise<{ default: T }>,
  fallback?: React.ComponentType
) => {
  const LazyComponent = React.lazy(importFunc);
  
  return React.forwardRef<any, React.ComponentProps<T>>((props, ref) => (
    <React.Suspense fallback={
      fallback ? React.createElement(fallback) : 
      <div className="flex items-center justify-center p-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    }>
      <LazyComponent {...(props as any)} ref={ref} />
    </React.Suspense>
  ));
};

// Background task management
class BackgroundTaskManager {
  private tasks: Set<() => void> = new Set();
  private isActive = true;

  constructor() {
    this.setupVisibilityHandling();
  }

  private setupVisibilityHandling() {
    const handleVisibilityChange = () => {
      this.isActive = !document.hidden;
      
      if (this.isActive) {
        console.log('[Performance] App became visible, resuming background tasks');
        this.resumeTasks();
      } else {
        console.log('[Performance] App hidden, pausing background tasks');
        this.pauseTasks();
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
  }

  addTask(task: () => void): () => void {
    this.tasks.add(task);
    
    // Return cleanup function
    return () => {
      this.tasks.delete(task);
    };
  }

  private pauseTasks() {
    // Tasks can check this.isActive before executing
    this.isActive = false;
  }

  private resumeTasks() {
    this.isActive = true;
    // Execute all tasks once when resuming
    this.tasks.forEach(task => {
      try {
        task();
      } catch (error) {
        console.error('[Performance] Background task error:', error);
      }
    });
  }

  get active() {
    return this.isActive;
  }
}

export const backgroundTaskManager = new BackgroundTaskManager();

// Reduced motion utilities
export const useReducedMotion = () => {
  const [prefersReducedMotion, setPrefersReducedMotion] = React.useState(false);

  React.useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    setPrefersReducedMotion(mediaQuery.matches);

    const handler = (e: MediaQueryListEvent) => {
      setPrefersReducedMotion(e.matches);
    };

    mediaQuery.addEventListener('change', handler);
    return () => mediaQuery.removeEventListener('change', handler);
  }, []);

  return prefersReducedMotion;
};

// Performance monitoring
export const performanceMonitor = {
  markStart: (name: string) => {
    if ('performance' in window && performance.mark) {
      performance.mark(`${name}-start`);
    }
  },

  markEnd: (name: string) => {
    if ('performance' in window && performance.mark && performance.measure) {
      performance.mark(`${name}-end`);
      performance.measure(name, `${name}-start`, `${name}-end`);
      
      const measurements = performance.getEntriesByName(name, 'measure');
      if (measurements.length > 0) {
        const duration = measurements[measurements.length - 1].duration;
        console.log(`[Performance] ${name}: ${duration.toFixed(2)}ms`);
      }
    }
  },

  measureRender: <T extends React.ComponentType>(
    Component: T,
    name?: string
  ): T => {
    const componentName = name || (Component as any).displayName || (Component as any).name || 'Component';
    
    return React.forwardRef((props, ref) => {
      React.useEffect(() => {
        performanceMonitor.markStart(`render-${componentName}`);
        
        return () => {
          performanceMonitor.markEnd(`render-${componentName}`);
        };
      });

      return React.createElement(Component as any, { ...props, ref });
    }) as unknown as T;
  }
};

// Memory management
export const memoryManager = {
  cleanup: () => {
    // Clear unused caches
    if ('caches' in window) {
      caches.keys().then(names => {
        names.forEach(name => {
          if (name.includes('old') || name.includes('temp')) {
            caches.delete(name);
          }
        });
      });
    }

    // Clear performance entries
    if ('performance' in window && performance.clearMeasures) {
      performance.clearMeasures();
      performance.clearMarks();
    }

    console.log('[Performance] Memory cleanup completed');
  },

  getMemoryInfo: () => {
    if ('memory' in performance) {
      const memory = (performance as any).memory;
      return {
        used: Math.round(memory.usedJSHeapSize / 1048576), // MB
        total: Math.round(memory.totalJSHeapSize / 1048576), // MB
        limit: Math.round(memory.jsHeapSizeLimit / 1048576) // MB
      };
    }
    return null;
  }
};

// Resource loading optimization
export const resourceLoader = {
  preloadRoute: (path: string) => {
    const link = document.createElement('link');
    link.rel = 'prefetch';
    link.href = path;
    document.head.appendChild(link);
  },

  preloadImage: (src: string): Promise<void> => {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve();
      img.onerror = reject;
      img.src = src;
    });
  },

  preloadImages: async (sources: string[]): Promise<void> => {
    await Promise.all(sources.map(src => resourceLoader.preloadImage(src)));
  }
};

// Battery optimization
export const batteryOptimizer = {
  async getBatteryInfo() {
    if ('getBattery' in navigator) {
      try {
        const battery = await (navigator as any).getBattery();
        return {
          level: battery.level,
          charging: battery.charging,
          chargingTime: battery.chargingTime,
          dischargingTime: battery.dischargingTime
        };
      } catch (error) {
        console.warn('[Performance] Battery API not available:', error);
        return null;
      }
    }
    return null;
  },

  async shouldReduceActivity(): Promise<boolean> {
    const battery = await this.getBatteryInfo();
    if (!battery) return false;

    // Reduce activity if battery is low and not charging
    return battery.level < 0.2 && !battery.charging;
  }
};
