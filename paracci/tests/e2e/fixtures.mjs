import { test as base, expect } from 'playwright/test';

import {
    cleanupProfileSet,
    createProfileSet,
    redactE2EText,
    redactedRuntimeOutput,
    startSourceRuntime,
    stopProcess,
} from '../../../tools/e2e/runtime.mjs';

function safeRequestLabel(request) {
    try {
        const url = new URL(request.url());
        return `${request.method()} ${url.origin}${url.pathname} [${request.resourceType()}]`;
    } catch {
        return `${request.method()} <invalid-url> [${request.resourceType()}]`;
    }
}

function isAllowedLoopbackUrl(rawUrl) {
    try {
        const url = new URL(rawUrl);
        return url.protocol === 'http:' && url.hostname === '127.0.0.1';
    } catch {
        return false;
    }
}

function isRelevantAppRequest(request) {
    let pathname;
    try {
        pathname = new URL(request.url()).pathname;
    } catch {
        return false;
    }
    return (
        pathname === '/favicon.ico'
        || pathname.startsWith('/static/')
        || pathname.startsWith('/api/')
        || ['document', 'script', 'stylesheet', 'font'].includes(request.resourceType())
    );
}

function createPolicyCollector(context, origin) {
    const failures = new Set();
    const record = message => failures.add(message);

    context.route('**/*', async route => {
        const request = route.request();
        if (!isAllowedLoopbackUrl(request.url())) {
            record(`external request blocked: ${safeRequestLabel(request)}`);
            await route.abort('blockedbyclient');
            return;
        }
        await route.continue();
    });

    context.on('request', request => {
        if (!isAllowedLoopbackUrl(request.url())) {
            record(`external request attempted: ${safeRequestLabel(request)}`);
        }
    });
    context.on('response', response => {
        const request = response.request();
        let responseOrigin;
        try {
            responseOrigin = new URL(request.url()).origin;
        } catch {
            return;
        }
        if (responseOrigin !== origin || response.status() < 400) return;
        if (!isRelevantAppRequest(request)) return;
        record(`http ${response.status()}: ${safeRequestLabel(request)}`);
    });
    context.on('requestfailed', request => {
        let requestOrigin;
        try {
            requestOrigin = new URL(request.url()).origin;
        } catch {
            return;
        }
        if (requestOrigin !== origin || !isRelevantAppRequest(request)) return;
        const failure = request.failure()?.errorText || 'request failed';
        if (request.isNavigationRequest() && failure.includes('net::ERR_ABORTED')) return;
        record(`request failed: ${safeRequestLabel(request)} ${failure}`);
    });

    return {
        attachPage(page) {
            page.on('pageerror', error => {
                record(`pageerror: ${error?.message || String(error)}`);
            });
            page.on('console', message => {
                if (message.type() === 'error') {
                    record(`console.error: ${message.text()}`);
                }
            });
        },
        failures() {
            return [...failures];
        },
    };
}

async function attachFailureLog(testInfo, runtime, policyFailures) {
    if (testInfo.status === testInfo.expectedStatus && policyFailures.length === 0) return;
    const sections = [];
    if (policyFailures.length > 0) {
        sections.push('--- browser policy failures ---', ...policyFailures);
    }
    const runtimeOutput = redactedRuntimeOutput(runtime);
    if (runtimeOutput) {
        sections.push('--- redacted runtime output ---', runtimeOutput);
    }
    await testInfo.attach('paracci-e2e-failure.log', {
        body: Buffer.from(sections.join('\n'), 'utf8'),
        contentType: 'text/plain',
    });
}

async function lockIfUnlocked(page) {
    if (page.isClosed()) return;
    await page.evaluate(async () => {
        if (window.location.pathname === '/unlock') return;
        const csrf = document.querySelector('meta[name="paracci-csrf-token"]')?.content;
        if (!csrf) return;
        await fetch('/api/lock', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'X-CSRF-Token': csrf,
                'X-Requested-With': 'XMLHttpRequest',
            },
        });
    }).catch(() => {});
}

export const test = base.extend({
    profileSet: async ({}, use) => {
        const profileSet = await createProfileSet();
        try {
            await use(profileSet);
        } finally {
            await cleanupProfileSet(profileSet);
        }
    },

    runtime: async ({ profileSet }, use) => {
        const runtime = await startSourceRuntime(profileSet);
        try {
            await use(runtime);
        } finally {
            await stopProcess(runtime.proc);
        }
    },

    app: async ({ browser, profileSet, runtime }, use, testInfo) => {
        const context = await browser.newContext({
            locale: 'en-US',
            viewport: { width: 1280, height: 900 },
            serviceWorkers: 'allow',
            acceptDownloads: false,
        });
        const policy = createPolicyCollector(context, runtime.entrypoint.origin);
        await context.addInitScript(() => {
            window.addEventListener('unhandledrejection', event => {
                const reason = event.reason;
                const name = reason?.name || '';
                const message = reason?.message || String(reason || 'Unhandled promise rejection');
                if (name === 'AbortError' || message === 'Transition was skipped') return;
                console.error(`[ParacciE2EUnhandledRejection] ${message}`);
            });
        });
        const page = await context.newPage();
        policy.attachPage(page);

        try {
            await use({ page, policy, profileSet, runtime });
        } finally {
            await lockIfUnlocked(page);
            await page.waitForTimeout(100).catch(() => {});
            const policyFailures = policy.failures().map(
                failure => redactE2EText(runtime, failure)
            );
            await attachFailureLog(testInfo, runtime, policyFailures);
            await context.close().catch(() => {});
            if (policyFailures.length > 0) {
                throw new Error(`Unexpected browser policy failures:\n${policyFailures.join('\n')}`);
            }
        }
    },
});

export { expect };
