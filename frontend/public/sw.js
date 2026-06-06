 

// Force new service worker to activate immediately (no waiting for tabs to close)
self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (event) { event.waitUntil(self.clients.claim()); });
self.addEventListener('push', function (event) {
    var payload = {};
    try { payload = event.data ? event.data.json() : {}; } catch (e) { payload = {}; }

    var title = payload.title || 'Kryptolog';
    var options = {
        body: payload.body || 'You have a new secure message',
        icon: '/icon-192.png',
        badge: '/icon-192.png',
        vibrate: [100, 50, 100],
        data: payload.data || {}
    };

    // iOS (and the userVisibleOnly contract) requires EVERY push to display a
    // notification — skipping showNotification gets the subscription revoked.
    // The backend already suppresses push for users whose app is focused
    // (websocket_manager.is_focused), so we don't double-guard here.
    event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', function (event) {
    event.notification.close();

    // Default URL to focus or open
    var urlToOpen = new URL('/', self.location.origin).href;

    event.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (clientList) {
            for (var i = 0; i < clientList.length; i++) {
                var client = clientList[i];
                if (client.url === urlToOpen && 'focus' in client) {
                    return client.focus();
                }
            }
            if (self.clients.openWindow) {
                return self.clients.openWindow(urlToOpen);
            }
        })
    );
});
