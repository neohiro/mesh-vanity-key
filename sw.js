// Service worker for the MeshCore vanity key generator.
//
// Caching strategy: stale-while-revalidate.
//   - Respond from cache immediately when available (keeps the app instant and
//     usable offline), while fetching a fresh copy in the background.
//   - The next load therefore picks up deploys automatically. An earlier
//     cache-first worker pinned to 'meshcore-vanity-v1' had no way to ship a
//     fix: users stayed on the old libsodium/index.html indefinitely, because
//     a cache name only changes when someone remembers to bump it.
//
// Bump CACHE_VERSION when the set of precached files changes so old caches are
// garbage collected on activate.

// Incremented whenever urlsToCache changes shape.
const CACHE_VERSION = 2;
const CACHE_NAME = `meshcore-vanity-v${CACHE_VERSION}`;

const urlsToCache = [
  '/',
  '/index.html',
  '/libsodium.js',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png',
];

// Only ever cache these. Anything else (analytics, fonts on a CDN, the GitHub
// Pages logo, ...) is passed straight to the network.
const isCacheable = (url) =>
  url.origin === self.location.origin &&
  (url.pathname === '/' ||
    url.pathname.endsWith('.html') ||
    url.pathname.endsWith('.js') ||
    url.pathname.endsWith('.json') ||
    url.pathname.endsWith('.png') ||
    url.pathname.endsWith('.css') ||
    url.pathname.endsWith('.webmanifest'));

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) =>
        // addAll() rejects wholesale if any single request fails, which would
        // leave the worker permanently uninstalled. Cache entries
        // individually and tolerate misses so a partial outage degrades
        // gracefully instead of bricking the offline app.
        Promise.all(
          urlsToCache.map((url) =>
            cache.add(new Request(url, { cache: 'reload' })).catch((err) => {
              console.warn('[SW] precache failed:', url, err);
            })
          )
        )
      )
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((cacheNames) =>
        Promise.all(
          cacheNames
            .filter((name) => name.startsWith('meshcore-vanity-v') && name !== CACHE_NAME)
            .map((name) => caches.delete(name))
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('fetch', (event) => {
  const { request } = event;

  // Never intercept non-GET: caches.match() on a POST would mismatch and the
  // response body would be unusable anyway.
  if (request.method !== 'GET') return;

  let url;
  try {
    url = new URL(request.url);
  } catch {
    return;
  }

  if (!isCacheable(url)) return;

  event.respondWith(
    caches.open(CACHE_NAME).then((cache) =>
      // 1. Try the cache first so repeat loads are instant and work offline.
      cache.match(request).then((cached) => {
        // 2. Kick off a background refresh regardless of cache hit. Await this
        //    via waitUntil() so the worker stays alive long enough to store it,
        //    but the cached response is handed back immediately.
        const network = fetch(request)
          .then((response) => {
            // Opaque (status 0) and error responses are not storable.
            if (response && response.status === 200 && response.type === 'basic') {
              return cache.put(request, response.clone()).then(() => response);
            }
            return response;
          })
          .catch((err) => {
            // Offline: fall back to whatever we cached, else let the browser
            // surface the network failure.
            console.warn('[SW] network failed for', request.url, err);
            return cached || Response.error();
          });

        if (cached) {
          event.waitUntil(network.catch(() => {}));
          return cached;
        }

        // Cold cache: the user waits for the network, but still gets an
        // offline page if that fails.
        return network;
      })
    )
  );
});
