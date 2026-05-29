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

    // Do not intercept non-GET/HEAD navigation requests (such as form POSTs).
    // Navigation POST requests carry their loopback and CSRF tokens via form parameters
    // injected by app.js. Intercepting them here would discard the request body.
    if (request.mode === 'navigate' && request.method !== 'GET' && request.method !== 'HEAD') {
        return false;
    }

    return !target.pathname.startsWith('/static/');
}

self.addEventListener('fetch', event => {
    if (!loopbackToken || !needsLoopbackAuthorization(event.request)) return;

    const headers = new Headers(event.request.headers);
    headers.set('X-Paracci-Token', loopbackToken);
    
    let request;
    if (event.request.mode === 'navigate') {
        const options = {
            method: event.request.method,
            headers: headers,
            credentials: event.request.credentials,
            mode: 'same-origin',
            redirect: event.request.redirect
        };
        if (event.request.referrer) {
            options.referrer = event.request.referrer;
        }
        request = new Request(event.request.url, options);
    } else {
        const options = { headers };
        if (event.request.referrer) {
            options.referrer = event.request.referrer;
        }
        request = new Request(event.request, options);
    }
    event.respondWith(fetch(request));
});
