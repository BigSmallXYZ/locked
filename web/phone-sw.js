// Locked's service worker on the paired phone (scope /phone/). It only shows notifications:
// no fetch handler, no caching of pages. A push carries a share token, the label and Claude's
// purpose, never a secret; the values are fetched and decrypted by the page after Face ID.

const SHARES = "/phone/__shares"; // recent share tokens, so the app can list them when opened directly

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

async function remember(d) {
  const cache = await caches.open("locked");
  const res = await cache.match(SHARES);
  const now = Date.now();
  const list = res ? await res.json().catch(() => []) : [];
  const next = [{ s: d.s, title: d.title, body: d.body, exp: d.exp, at: now }, ...list.filter((x) => x.exp > now && x.s !== d.s)].slice(0, 20);
  await cache.put(SHARES, new Response(JSON.stringify(next), { headers: { "Content-Type": "application/json" } }));
}

self.addEventListener("push", (event) => {
  let d = {};
  try {
    d = event.data ? event.data.json() : {};
  } catch {}
  const share = d.t === "share" && typeof d.s === "string";
  // iOS drops subscriptions that receive pushes without a notification, so every push shows one.
  event.waitUntil(
    (async () => {
      await self.registration.showNotification(d.title || "Locked", {
        body: d.body || "",
        icon: "/assets/phone-icon-192.png",
        badge: "/assets/phone-badge-96.png",
        tag: share ? `share-${d.s.slice(0, 12)}` : "info",
        data: { url: share ? `/phone/#s=${d.s}` : "/phone/" },
        requireInteraction: share,
      });
      if (share) {
        await remember(d).catch(() => {});
        await fetch(`/phone/api/s/${d.s}/delivered`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }).catch(() => {});
      }
    })(),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = new URL(event.notification.data?.url || "/phone/", self.location.origin).href;
  event.waitUntil(
    (async () => {
      const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      const open = windows.find((c) => new URL(c.url).pathname.startsWith("/phone/"));
      if (open) {
        await open.focus();
        open.postMessage({ type: "open", url });
      } else {
        await self.clients.openWindow(url);
      }
    })(),
  );
});
