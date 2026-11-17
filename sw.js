// AegisMobile Ultimate v3.5 (PERISAI Standard) - Hardened Offline-First Service Worker
const CACHE_NAME = 'aegis-ultimate-v3.5-perisai';
const ASSETS = [
  './',
  './index.html',
  './style.css',
  './app.js',
  './manifest.json',
  './icons/icon-192.png',
  './icons/icon-512.png'
];
const CACHEABLE_PATHS = new Set(ASSETS.map((p) => new URL(p, self.location.href).pathname));

const ALLOWED_MIME_PREFIXES = [
  'text/html',
  'text/css',
  'application/javascript',
  'text/javascript',
  'application/json',
  'application/manifest+json',
  'image/png'
];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS))
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      )
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  const reqUrl = new URL(event.request.url);
  if (reqUrl.origin !== self.location.origin) return;

  const isStaticAsset = CACHEABLE_PATHS.has(reqUrl.pathname) && !reqUrl.search;

  event.respondWith(
    fetch(event.request)
      .then((networkResponse) => {
        if (isStaticAsset && networkResponse && networkResponse.status === 200 && networkResponse.type === 'basic') {
          const contentType = (networkResponse.headers.get('content-type') || '').toLowerCase();
          const mimeSafe = ALLOWED_MIME_PREFIXES.some((prefix) => contentType.startsWith(prefix));
          if (mimeSafe) {
            const responseToCache = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(event.request, responseToCache);
            });
          }
        }
        return networkResponse;
      })
      .catch(() => {
        return caches.match(event.request, { ignoreSearch: true }).then((cachedResponse) => {
          return cachedResponse || caches.match('./index.html');
        });
      })
  );
});
