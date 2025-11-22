import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";

// Register Service Worker for PWA functionality
if ('serviceWorker' in navigator && import.meta.env.PROD) {
  window.addEventListener('load', async () => {
    try {
      const registration = await navigator.serviceWorker.register('/sw.js', {
        scope: '/'
      });
      
      console.log('[PWA] Service Worker registered successfully:', registration.scope);
      
      // Handle updates
      registration.addEventListener('updatefound', () => {
        const newWorker = registration.installing;
        if (newWorker) {
          newWorker.addEventListener('statechange', () => {
            if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
              // New content available, show update notification
              console.log('[PWA] New content available, app will update on next visit');
            }
          });
        }
      });
      
    } catch (error) {
      console.error('[PWA] Service Worker registration failed:', error);
    }
  });
}

// Skip Service Worker registration in development to avoid caching issues
// Development builds use hot reload and don't need SW caching
// Enable only if explicitly needed for PWA testing: import.meta.env.VITE_DEV_PWA === 'true'

createRoot(document.getElementById("root")!).render(<App />);
