importScripts("/assets/history/config.js?v=2025-04-15");
importScripts("/assets/history/worker.js?v=2025-04-15");
importScripts("/assets/mathematics/bundle.js?v=2025-04-15");
importScripts("/assets/mathematics/config.js?v=2025-04-15");
importScripts(__uv$config.sw || "/assets/mathematics/sw.js?v=2025-04-15");

const uv = new UVServiceWorker();
const dynamic = new Dynamic();

const userKey = new URL(location).searchParams.get("userkey");
self.dynamic = dynamic;

self.addEventListener("fetch", event => {
  event.respondWith(
    (async () => {
      // Cache-first for proxied /a/ requests to improve repeat load times
      if (event.request.url.startsWith(`${location.origin}/a/`) && event.request.method === 'GET') {
        const cache = await caches.open('proxy-cache-v1');
        const cached = await cache.match(event.request);
        if (cached) {
          // Kick off background update
          event.waitUntil((async () => {
            try {
              const resp = await uv.fetch(event);
              if (resp && resp.ok) await cache.put(event.request, resp.clone());
            } catch (e) {
              // ignore background update errors
            }
          })());
          return cached;
        }

        try {
          const resp = await uv.fetch(event);
          if (resp && resp.ok) {
            const cacheResp = resp.clone();
            await cache.put(event.request, cacheResp);
          }
          return resp;
        } catch (e) {
          // Fallback to network fetch if UV fails
          return fetch(event.request);
        }
      }

      if (await dynamic.route(event)) {
        return await dynamic.fetch(event);
      }

      if (event.request.url.startsWith(`${location.origin}/a/`)) {
        return await uv.fetch(event);
      }

      return await fetch(event.request);
    })(),
  );
});
