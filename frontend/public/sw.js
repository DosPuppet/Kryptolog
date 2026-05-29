/* eslint-disable no-restricted-globals */

// Force new service worker to activate immediately (no waiting for tabs to close)
self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (event) { event.waitUntil(self.clients.claim()); });
self.addEventListener('push', function (event) {
    if (event.data) {
        const payload = event.data.json();
        const options = {
            body: payload.body,
            icon: '/icon-192.png',
            badge: '/icon-192.png',
            vibrate: [100, 50, 100],
            data: payload.data
        };

        event.waitUntil(
            self.clients.matchAll({ type: 'window', includeUncontrolled: true })
                .then(function (clients) {
                    // If any app window is focused, skip the notification
                    var isFocused = clients.some(function (c) { return c.visibilityState === 'visible'; });
                    if (isFocused) return;
                    return self.registration.showNotification(payload.title, options);
                })
        );
    }
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
