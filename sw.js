/* Tuner offline shell — caches the app shell only. Playlists, API data,
   stream manifests and segments always go to network (never cached). */
const CACHE = 'tuner-shell-v1';
const SHELL = ['./', 'index.html', 'manifest.webmanifest', 'icon.svg'];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches
      .open(CACHE)
      .then((c) => c.addAll(SHELL))
      .then(() => self.skipWaiting())
      .catch(() => {})
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches
      .keys()
      .then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET') return;
  const u = new URL(e.request.url);
  if (u.origin !== self.location.origin) return; // streams, fonts, APIs: network only
  if (/\.(m3u8?|ts|m4s|mp4|key)(\?|#|$)/i.test(u.pathname)) return; // live media
  if (u.pathname.endsWith('.m3u') || u.pathname.includes('/api/')) return;
  e.respondWith(
    caches.match(e.request).then((hit) => {
      const net = fetch(e.request)
        .then((r) => {
          if (r && r.ok) {
            const c = r.clone();
            caches.open(CACHE).then((cc) => cc.put(e.request, c));
          }
          return r;
        })
        .catch(() => hit);
      return hit || net;
    })
  );
});
