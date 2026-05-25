(function bootstrapLoopbackAuthorization() {
    'use strict';

    const config = document.getElementById('paracciBootstrapConfig');
    const status = document.getElementById('bootstrapStatus');
    const token = config?.dataset.token || '';
    const target = config?.dataset.target || '/';
    const workerUrl = '/static/js/loopback-auth-sw.js';

    function failClosed() {
        if (status) {
            status.textContent = 'Secure local authorization could not be initialized.';
        }
    }

    function seedWorker(worker) {
        return new Promise((resolve, reject) => {
            const timeout = window.setTimeout(
                () => reject(new Error('Authorization worker did not respond.')),
                3000
            );
            const channel = new MessageChannel();
            channel.port1.onmessage = event => {
                window.clearTimeout(timeout);
                if (event.data?.ok === true) {
                    resolve();
                } else {
                    reject(new Error('Authorization worker rejected token.'));
                }
            };
            worker.postMessage(
                { type: 'paracci:set-loopback-token', token },
                [channel.port2]
            );
        });
    }

    async function start() {
        if (!token || !target.startsWith('/') || target.startsWith('//')) {
            throw new Error('Invalid local bootstrap data.');
        }
        if (!('serviceWorker' in navigator)) {
            throw new Error('Service workers are unavailable.');
        }

        const registration = await navigator.serviceWorker.register(workerUrl, { scope: '/' });
        const activeRegistration = await navigator.serviceWorker.ready;
        const worker = activeRegistration.active || registration.active;
        if (!worker) {
            throw new Error('Authorization worker did not activate.');
        }
        await seedWorker(worker);
        window.location.replace(target);
    }

    start().catch(failClosed);
})();
