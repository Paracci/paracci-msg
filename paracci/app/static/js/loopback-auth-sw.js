'use strict';

let loopbackToken = '';

self.addEventListener('install', event => {
    event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', event => {
    event.waitUntil(self.clients.claim());
});

self.addEventListener('message', event => {
    const data = event.data || {};
    const reply = event.ports && event.ports[0];
    if (
        data.type !== 'paracci:set-loopback-token'
        || typeof data.token !== 'string'
        || !data.token
    ) {
        if (reply) reply.postMessage({ ok: false });
        return;
    }
    loopbackToken = data.token;
    if (reply) reply.postMessage({ ok: true });
});

function needsLoopbackAuthorization(request) {
    const target = new URL(request.url);
    if (target.origin !== self.location.origin) return false;
    if (target.pathname === '/__paracci_bootstrap') return false;
    if (target.pathname === '/favicon.ico') return false;
    return !target.pathname.startsWith('/static/');
}

self.addEventListener('fetch', event => {
    if (!loopbackToken || !needsLoopbackAuthorization(event.request)) return;

    const headers = new Headers(event.request.headers);
    headers.set('X-Paracci-Token', loopbackToken);
    event.respondWith(fetch(new Request(event.request, { headers })));
});
