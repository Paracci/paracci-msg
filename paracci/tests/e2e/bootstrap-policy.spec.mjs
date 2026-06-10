import { BootstrapPage } from './bootstrap-page.mjs';
import { expect, test } from './fixtures.mjs';

test('@phase1 bootstrap-only source runtime enforces local browser policy', async ({ app }) => {
    const { page, profileSet, runtime } = app;

    const unbootstrapped = await fetch(`${runtime.entrypoint.origin}/settings`, {
        redirect: 'manual',
    });
    expect(unbootstrapped.status).toBe(403);

    const bootstrap = new BootstrapPage(page);
    await bootstrap.open(runtime.entrypoint.href);
    await expect(bootstrap.authForm).toBeVisible();
    await expect(bootstrap.passphraseInput).toBeAttached();
    expect(await bootstrap.securityState()).toEqual({
        pathname: '/unlock',
        hostname: '127.0.0.1',
        authMode: 'unlock',
        hasBrowserToken: true,
        hasCsrfToken: true,
        hasServiceWorkerController: true,
    });

    await bootstrap.unlock(profileSet.passphrase);
    expect(new URL(page.url()).hostname).toBe('127.0.0.1');
    expect(new URL(page.url()).pathname).toBe('/');
    await expect(page.locator('body')).toBeVisible();
    await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});
    await page.waitForTimeout(750);
});
