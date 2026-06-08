import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineConfig } from 'playwright/test';

const REPO_ROOT = path.dirname(fileURLToPath(import.meta.url));
const OUTPUT_ROOT = path.join(REPO_ROOT, 'output', 'playwright');

export default defineConfig({
    testDir: './paracci/tests/e2e',
    outputDir: path.join(OUTPUT_ROOT, 'test-results'),
    fullyParallel: false,
    forbidOnly: true,
    workers: 1,
    retries: 0,
    timeout: 120_000,
    expect: {
        timeout: 10_000,
    },
    reporter: [
        ['line'],
        ['html', { outputFolder: path.join(OUTPUT_ROOT, 'report'), open: 'never' }],
    ],
    use: {
        headless: true,
        locale: 'en-US',
        viewport: { width: 1280, height: 900 },
        serviceWorkers: 'allow',
        testIdAttribute: 'data-e2e',
        acceptDownloads: false,
        trace: 'retain-on-failure',
        screenshot: 'only-on-failure',
        video: 'off',
        launchOptions: {
            args: [
                '--disable-background-networking',
                '--disable-component-update',
                '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1',
            ],
        },
    },
});
