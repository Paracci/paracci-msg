export class BootstrapPage {
    constructor(page) {
        this.page = page;
        this.authForm = page.locator('#authForm');
        this.passphraseInput = page.locator('#pinInput');
        this.submitButton = page.locator('#submitBtn');
        this.linuxFallback = page.locator('#allowLinuxPassphraseFallback');
    }

    async open(entrypoint) {
        const url = new URL(entrypoint);
        if (
            url.protocol !== 'http:'
            || url.hostname !== '127.0.0.1'
            || url.pathname !== '/__paracci_bootstrap'
        ) {
            throw new Error('Refusing to open an invalid E2E bootstrap entrypoint.');
        }
        await this.page.goto(entrypoint, { waitUntil: 'domcontentloaded' });
        await this.page.waitForURL(urlValue => new URL(urlValue).pathname === '/unlock');
    }

    async securityState() {
        return this.page.evaluate(() => ({
            pathname: window.location.pathname,
            hostname: window.location.hostname,
            authMode: document.getElementById('authForm')?.dataset.mode || '',
            hasBrowserToken: Boolean(
                document.querySelector('meta[name="paracci-browser-token"]')?.content
            ),
            hasCsrfToken: Boolean(
                document.querySelector('meta[name="paracci-csrf-token"]')?.content
            ),
            hasServiceWorkerController: Boolean(navigator.serviceWorker?.controller),
        }));
    }

    async unlock(passphrase) {
        await this.passphraseInput.fill(passphrase);
        if (await this.linuxFallback.isVisible().catch(() => false)) {
            await this.linuxFallback.check();
        }
        await Promise.all([
            this.page.waitForURL(urlValue => new URL(urlValue).pathname !== '/unlock'),
            this.submitButton.click(),
        ]);
    }
}
