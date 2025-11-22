// Service Worker for ProjectEnt PWA
const SW_VERSION = 'v1.2.0';
const STATIC_CACHE = `projectent-static-${SW_VERSION}`;
const API_CACHE = `projectent-api-${SW_VERSION}`;
const OFFLINE_CACHE = `projectent-offline-${SW_VERSION}`;

// Core assets that must be cached for offline functionality
const CORE_ASSETS = [
  '/',
  '/manifest.webmanifest',
  '/icon-192x192.png',
  '/icon-512x512.png',
  '/offline.html' // We'll create this fallback page
];

// Test-related assets that should be cached for offline tests
const TEST_ASSETS = [
  '/test/',
  '/api/blocks',
  '/api/variants/'
];

// API routes that can work offline with cache-first strategy
const OFFLINE_FIRST_APIS = [
  '/api/blocks',
  '/api/variants/',
  '/api/subjects/',
  '/api/questions/',
  '/api/answers/'
];

// API routes that need fresh data - stale-while-revalidate
const NETWORK_FIRST_APIS = [
  '/api/profile',
  '/api/notifications',
  '/api/user/ranking',
  '/api/analytics'
];

// Install event - cache core assets
self.addEventListener('install', (event) => {
  console.log(`[SW] Install event - ${SW_VERSION}`);
  
  event.waitUntil(
    Promise.all([
      // Cache core assets
      caches.open(STATIC_CACHE).then(cache => {
        console.log('[SW] Caching core assets');
        return cache.addAll(CORE_ASSETS);
      }),
      // Pre-cache offline page
      caches.open(OFFLINE_CACHE).then(cache => {
        return cache.add('/offline.html');
      })
    ]).then(() => {
      console.log('[SW] Core assets cached successfully');
      return self.skipWaiting();
    }).catch(error => {
      console.error('[SW] Failed to cache core assets:', error);
      throw error;
    })
  );
});

// Activate event - clean old caches
self.addEventListener('activate', (event) => {
  console.log('[SW] Activate event');
  
  event.waitUntil(
    caches.keys()
      .then(cacheNames => {
        return Promise.all(
          cacheNames
            .filter(cacheName => {
              return cacheName.startsWith('projectent-') && 
                     cacheName !== STATIC_CACHE && 
                     cacheName !== API_CACHE &&
                     cacheName !== OFFLINE_CACHE;
            })
            .map(cacheName => {
              console.log('[SW] Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            })
        );
      })
      .then(() => {
        console.log('[SW] Claiming clients');
        return self.clients.claim();
      })
  );
});

// Fetch event - implement smart caching strategies
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests and external domains
  if (request.method !== 'GET' || !url.origin.includes(self.location.origin)) {
    return;
  }

  // Skip chrome-extension and other non-http(s) requests
  if (!url.protocol.startsWith('http')) return;

  // Navigation requests - network first with offline fallback
  if (request.mode === 'navigate') {
    event.respondWith(handleNavigation(request));
    return;
  }

  // API requests - different strategies based on route
  if (url.pathname.startsWith('/api/')) {
    // Test data APIs - cache first for offline capability
    if (OFFLINE_FIRST_APIS.some(route => url.pathname.startsWith(route))) {
      event.respondWith(cacheFirst(request, API_CACHE, true));
      return;
    }
    
    // Dynamic APIs - stale while revalidate
    if (NETWORK_FIRST_APIS.some(route => url.pathname.startsWith(route))) {
      event.respondWith(staleWhileRevalidate(request, API_CACHE));
      return;
    }
    
    // Default API strategy
    event.respondWith(staleWhileRevalidate(request, API_CACHE));
    return;
  }

  // Static assets - cache first
  event.respondWith(cacheFirst(request, STATIC_CACHE, false));
});

// Handle navigation requests with network-first + offline fallback
async function handleNavigation(request) {
  try {
    // Try network first
    const response = await fetch(request);
    
    // Cache successful responses
    if (response.ok) {
      const cache = await caches.open(STATIC_CACHE);
      cache.put(request, response.clone());
    }
    
    return response;
  } catch (error) {
    console.log('[SW] Navigation offline, serving cached or fallback');
    
    // Try cached version
    const cache = await caches.open(STATIC_CACHE);
    const cached = await cache.match(request);
    if (cached) return cached;
    
    // Try index for SPA routing
    const indexCached = await cache.match('/');
    if (indexCached) return indexCached;
    
    // Last resort: offline page
    const offlineCache = await caches.open(OFFLINE_CACHE);
    const offlinePage = await offlineCache.match('/offline.html');
    return offlinePage || new Response('Offline', { status: 503 });
  }
}

// Cache-first strategy with network update
async function cacheFirst(request, cacheName, updateInBackground = false) {
  try {
    const cache = await caches.open(cacheName);
    const cached = await cache.match(request);
    
    if (cached) {
      console.log('[SW] Serving from cache:', request.url);
      
      // Update cache in background if requested
      if (updateInBackground) {
        fetch(request).then(response => {
          if (response.ok) {
            cache.put(request, response.clone());
          }
        }).catch(() => {}); // Silent fail for background updates
      }
      
      return cached;
    }

    console.log('[SW] Fetching and caching:', request.url);
    const response = await fetch(request);
    
    if (response.ok) {
      cache.put(request, response.clone());
    }
    
    return response;
  } catch (error) {
    console.error('[SW] Cache-first failed:', error);
    
    // Return cached version if available
    const cache = await caches.open(cacheName);
    const cached = await cache.match(request);
    if (cached) {
      console.log('[SW] Returning stale cache due to network error');
      return cached;
    }
    
    // API error response
    if (request.url.includes('/api/')) {
      return new Response(
        JSON.stringify({ 
          error: 'Offline', 
          message: 'Нет подключения к интернету',
          cached: false
        }),
        { 
          status: 503,
          statusText: 'Service Unavailable',
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    throw error;
  }
}

// Stale-while-revalidate strategy for API requests
async function staleWhileRevalidate(request, cacheName) {
  try {
    const cache = await caches.open(cacheName);
    const cached = await cache.match(request);
    
    // Always try to fetch in background
    const fetchPromise = fetch(request)
      .then(response => {
        if (response.status === 200) {
          cache.put(request, response.clone());
        }
        return response;
      })
      .catch(error => {
        console.error('[SW] Fetch failed:', error);
        return null;
      });

    // Return cached version immediately if available
    if (cached) {
      console.log('[SW] Serving cached API response:', request.url);
      return cached;
    }

    // Wait for network if no cache
    const response = await fetchPromise;
    if (response) {
      return response;
    }

    // Offline fallback for API
    return new Response(
      JSON.stringify({ 
        error: 'Offline', 
        message: 'Нет подключения к интернету' 
      }),
      { 
        status: 503,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  } catch (error) {
    console.error('[SW] Stale-while-revalidate failed:', error);
    throw error;
  }
}

// Background sync for offline data
self.addEventListener('sync', (event) => {
  console.log('[SW] Background sync event:', event.tag);
  
  if (event.tag === 'test-sync') {
    event.waitUntil(syncOfflineTests());
  }
});

// Sync offline test results
async function syncOfflineTests() {
  try {
    console.log('[SW] Syncing offline tests');
    
    // This would integrate with IndexedDB to get pending tests
    // and sync them to the server
    const response = await fetch('/api/sync/tests', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        action: 'sync_offline_tests'
      })
    });

    if (response.ok) {
      console.log('[SW] Tests synced successfully');
    }
  } catch (error) {
    console.error('[SW] Test sync failed:', error);
    // Will retry on next sync event
    throw error;
  }
}

// Push notification handling
self.addEventListener('push', (event) => {
  console.log('[SW] Push notification received');
  
  let notificationData = {
    title: 'ProjectEnt',
    body: 'Новое уведомление',
    icon: '/icon-192x192.png',
    badge: '/icon-96x96.png',
    tag: 'default'
  };

  if (event.data) {
    try {
      const data = event.data.json();
      notificationData = { ...notificationData, ...data };
    } catch (error) {
      console.error('[SW] Error parsing push data:', error);
    }
  }

  event.waitUntil(
    self.registration.showNotification(notificationData.title, {
      body: notificationData.body,
      icon: notificationData.icon,
      badge: notificationData.badge,
      tag: notificationData.tag,
      requireInteraction: true,
      actions: [
        {
          action: 'open',
          title: 'Открыть',
          icon: '/icon-96x96.png'
        }
      ]
    })
  );
});

// Notification click handling
self.addEventListener('notificationclick', (event) => {
  console.log('[SW] Notification clicked:', event.notification.tag);
  
  event.notification.close();

  const urlToOpen = event.action === 'open' || !event.action 
    ? '/' 
    : `/${event.action}`;

  event.waitUntil(
    self.clients.matchAll({ type: 'window' })
      .then(clients => {
        // Check if app is already open
        for (const client of clients) {
          if (client.url.includes(self.location.origin)) {
            client.focus();
            client.navigate(urlToOpen);
            return;
          }
        }
        
        // Open new window
        return self.clients.openWindow(urlToOpen);
      })
  );
});