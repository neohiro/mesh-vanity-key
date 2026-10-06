// Service worker for the MeshCore vanity key generator.
//
// Caching strategy, split by request type:
//   - Navigation (the HTML document): NETWORK-FIRST, cache as offline fallback.
//   - Static assets (libsodium.js, worker.js, icons): cache-first, revalidating
//     in the background so repeat loads are instant and deploys land next load.
//
// This started as stale-while-revalidate for everything, which turned out to be
// wrong for the document. An earlier cache-first worker pinned to
// 'meshcore-vanity-v1' had no way to ship a fix at all: users stayed on the old
// libsodium/index.html indefinitely, because a cache name only changes when
// someone remembers to bump it. Bumping it fixed that but left a subtler version
// of the same bug -- with the cached document handed back first, every deploy
// stayed invisible until the SECOND reload. For a single-page app whose entire
// UI, validation and estimation live in that one file, running stale code while
// appearing current is worse than the extra round trip.
//
// Bump CACHE_VERSION when the set of precached files changes so old caches are
// garbage collected on activate.

// Incremented whenever the precached file list changes shape.
//
// Bumped to 5 for the repository rename (meshcore-meshtastic-vanity-key ->
// mesh-vanity-key). The cache name is renamed to match, and the
// garbage-collection filter below is kept prefix-agnostic so it still clears the
// caches written under the old names rather than stranding them on disk.
const CACHE_VERSION = 5;
const CACHE_NAME = `mesh-vanity-v${CACHE_VERSION}`;
const CACHE_NAME_PREFIXES = ['meshcore-vanity-v', 'meshcore-meshtastic-vanity-v', 'mesh-vanity-v'];

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
            .filter((name) =>
                CACHE_NAME_PREFIXES.some((p) => name.startsWith(p)) && name !== CACHE_NAME)
            .map((name) => caches.delete(name))
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') self.skipWaiting();
});

// Navigation requests (the HTML document) are NETWORK-FIRST, deliberately.
//
// They used to be served cache-first with a background refresh, which made
// every deploy invisible until the SECOND reload: the first load handed back
// the previously cached index.html and only refreshed it for next time. For an
// app whose whole UI lives in that one document, that means running stale
// validation and stale markup while appearing current. HTML is a single small
// file, so fetching it first costs little, and the cache is still the offline
// fallback.
//
// Static assets below stay cache-first: they change rarely, so repeat loads
// stay instant and offline-capable.
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

  // Fetch, and store a fresh copy for next time.
  const fromNetwork = async () => {
    const response = await fetch(request);
    // Opaque (status 0) and error responses are not storable.
    if (response && response.status === 200 && response.type === 'basic') {
      const copy = response.clone();
      event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.put(request, copy))
      );
    }
    return response;
  };

  event.respondWith((async () => {
    const cache = await caches.open(CACHE_NAME);

    if (request.mode === 'navigate') {
      try {
        return await fromNetwork();
      } catch (err) {
        // Offline: fall back to the cached document so the app still loads.
        const cached = await cache.match(request)
          || await cache.match('/index.html')
          || await cache.match('/');
        if (cached) return cached;
        return Response.error();
      }
    }

    const cached = await cache.match(request);
    if (cached) {
      event.waitUntil(fromNetwork().catch(() => {}));
      return cached;
    }

    try {
      return await fromNetwork();
    } catch (err) {
      console.warn('[SW] network failed for', request.url, err);
      return Response.error();
    }
  })());
});
