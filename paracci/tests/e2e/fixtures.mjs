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
        return `${request.method()} ${url.origin}${url.pathname}${url.search} [${request.resourceType()}]`;
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

function requestParts(request) {
    try {
        const url = new URL(request.url());
        return {
            method: request.method().toUpperCase(),
            origin: url.origin,
            pathname: url.pathname,
            search: url.search,
        };
    } catch {
        return null;
    }
}

function createExpectedHttpFailure(scope) {
    const expected = {
        method: String(scope.method || '').toUpperCase(),
        pathname: String(scope.pathname || ''),
        search: String(scope.search || ''),
        status: Number(scope.status),
        step: String(scope.step || ''),
        active: true,
        matched: false,
    };
    if (
        !expected.method
        || !expected.pathname.startsWith('/')
        || !Number.isInteger(expected.status)
        || expected.status < 400
        || !expected.step
    ) {
        throw new Error('Expected negative HTTP scope must include method, pathname, status, and step.');
    }
    return expected;
}

function expectedHttpFailureMatches(scope, response) {
    const request = response.request();
    const parts = requestParts(request);
    return Boolean(
        scope.active
        && parts
        && parts.method === scope.method
        && parts.pathname === scope.pathname
        && parts.search === scope.search
        && response.status() === scope.status
    );
}

function isExpectedBrowserAbort(request, failure, origin) {
    const parts = requestParts(request);
    return Boolean(
        failure.includes('net::ERR_ABORTED')
        && parts
        && parts.origin === origin
        && parts.method === 'GET'
        && parts.pathname === '/'
        && parts.search === ''
        && request.resourceType() === 'fetch'
    );
}

function createPolicyCollector(context, origin, label = 'app') {
    const failures = new Set();
    const expectedHttpFailures = new Set();
    const record = message => failures.add(`[${label}] ${message}`);

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
        const parts = requestParts(request);
        if (!parts || parts.origin !== origin || response.status() < 400) return;
        for (const scope of expectedHttpFailures) {
            if (expectedHttpFailureMatches(scope, response)) {
                scope.matched = true;
                return;
            }
        }
        record(`http ${response.status()}: ${safeRequestLabel(request)}`);
    });
    context.on('requestfailed', request => {
        const parts = requestParts(request);
        if (!parts || parts.origin !== origin) return;
        const failure = request.failure()?.errorText || 'request failed';
        if (request.isNavigationRequest() && failure.includes('net::ERR_ABORTED')) return;
        if (isExpectedBrowserAbort(request, failure, origin)) return;
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
        async expectHttpFailure(scope, action) {
            const expected = createExpectedHttpFailure(scope);
            expectedHttpFailures.add(expected);
            try {
                const result = await action();
                return { result, matched: expected.matched };
            } finally {
                expected.active = false;
                expectedHttpFailures.delete(expected);
            }
        },
    };
}

function normalizeRuntimes(runtimes) {
    return Array.isArray(runtimes) ? runtimes : [runtimes];
}

function redactWithRuntimes(runtimes, value) {
    return normalizeRuntimes(runtimes).reduce(
        (current, runtime) => redactE2EText(runtime, current),
        value
    );
}

async function attachFailureLog(testInfo, runtimes, policyFailures) {
    if (testInfo.status === testInfo.expectedStatus && policyFailures.length === 0) return;
    const sections = [];
    if (policyFailures.length > 0) {
        sections.push('--- browser policy failures ---', ...policyFailures);
    }
    for (const runtime of normalizeRuntimes(runtimes)) {
        const runtimeOutput = redactedRuntimeOutput(runtime);
        if (runtimeOutput) {
            sections.push('--- redacted runtime output ---', runtimeOutput);
        }
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

async function createAppContext(browser, runtime, { acceptDownloads = false, label = 'app' } = {}) {
    const context = await browser.newContext({
        locale: 'en-US',
        viewport: { width: 1280, height: 900 },
        serviceWorkers: 'allow',
        acceptDownloads,
    });
    const policy = createPolicyCollector(context, runtime.entrypoint.origin, label);
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
    return { context, page, policy };
}

async function lockAppContext(appContext) {
    if (!appContext) return;
    await lockIfUnlocked(appContext.page);
    await appContext.page?.waitForTimeout(100).catch(() => {});
}

async function closeAppContext(appContext) {
    if (!appContext) return;
    await appContext.context?.close().catch(() => {});
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
        const appContext = await createAppContext(browser, runtime);

        try {
            await use({
                page: appContext.page,
                policy: appContext.policy,
                profileSet,
                runtime,
            });
        } finally {
            await lockAppContext(appContext);
            const policyFailures = appContext.policy.failures().map(
                failure => redactE2EText(runtime, failure)
            );
            await attachFailureLog(testInfo, runtime, policyFailures);
            await closeAppContext(appContext);
            if (policyFailures.length > 0) {
                throw new Error(`Unexpected browser policy failures:\n${policyFailures.join('\n')}`);
            }
        }
    },

    sessionPair: async ({ browser, profileSet }, use, testInfo) => {
        const runtimes = [];
        let xContext;
        let yContext;
        try {
            const runtimeX = await startSourceRuntime(profileSet, profileSet.dataX);
            runtimes.push(runtimeX);
            const runtimeY = await startSourceRuntime(profileSet, profileSet.dataY);
            runtimes.push(runtimeY);
            xContext = await createAppContext(browser, runtimeX, {
                acceptDownloads: true,
                label: 'x',
            });
            yContext = await createAppContext(browser, runtimeY, {
                acceptDownloads: true,
                label: 'y',
            });

            await use({
                profileSet,
                x: {
                    page: xContext.page,
                    policy: xContext.policy,
                    runtime: runtimeX,
                },
                y: {
                    page: yContext.page,
                    policy: yContext.policy,
                    runtime: runtimeY,
                },
            });
        } finally {
            await lockAppContext(yContext);
            await lockAppContext(xContext);
            const policyFailures = [
                ...(xContext?.policy.failures() || []),
                ...(yContext?.policy.failures() || []),
            ].map(failure => redactWithRuntimes(runtimes, failure));
            await attachFailureLog(testInfo, runtimes, policyFailures);
            await closeAppContext(yContext);
            await closeAppContext(xContext);
            for (const runtime of runtimes.reverse()) {
                await stopProcess(runtime.proc);
            }
            if (policyFailures.length > 0) {
                throw new Error(`Unexpected browser policy failures:\n${policyFailures.join('\n')}`);
            }
        }
    },
});

export { expect };
