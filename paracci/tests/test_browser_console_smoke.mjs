import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
    parseBootstrapEntrypoint,
    redactSensitive,
    SmokeFailure,
} from '../../tools/ci/browser_console_smoke.mjs';

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(TEST_DIR, '..', '..');

test('parseBootstrapEntrypoint extracts the no-gui launch URL without logging secrets', () => {
    const launchSecret = 'launch-token-abcdefghijklmnopqrstuvwxyz1234567890';
    const line = `  ${'http://127.0.0.1:54321/__paracci_bootstrap'}?token=${launchSecret}&next=/`;

    const parsed = parseBootstrapEntrypoint(line, 54321);

    assert.equal(parsed.href, `http://127.0.0.1:54321/__paracci_bootstrap?token=${launchSecret}&next=/`);
    assert.equal(parsed.origin, 'http://127.0.0.1:54321');
    assert.equal(parsed.port, 54321);
    assert.equal(parsed.token, launchSecret);
    assert.equal(parsed.next, '/');
});

test('parseBootstrapEntrypoint rejects unexpected ports', () => {
    const launchSecret = 'launch-token-abcdefghijklmnopqrstuvwxyz1234567890';
    const line = `http://127.0.0.1:54321/__paracci_bootstrap?token=${launchSecret}&next=/`;

    assert.throws(
        () => parseBootstrapEntrypoint(line, 54322),
        SmokeFailure
    );
});

test('redactSensitive removes tokens, auth headers, and local path material', () => {
    const launchSecret = 'launch-token-abcdefghijklmnopqrstuvwxyz1234567890';
    const csrfSecret = 'csrf-token-abcdefghijklmnopqrstuvwxyz1234567890';
    const nativeSecret = 'native-save-token-abcdefghijklmnopqrstuvwxyz1234567890';
    const repoRoot = REPO_ROOT;
    const tempRoot = path.join(path.dirname(REPO_ROOT), 'paracci-smoke-temp');
    const windowsPath = ['C:', 'Users', 'private-user', 'Desktop', 'paracci-msg'].join('\\');
    const linuxPath = ['', 'home', 'private-user', '.cache', 'paracci-smoke'].join('/');
    const input = [
        `url=http://127.0.0.1:54321/__paracci_bootstrap?token=${launchSecret}&next=/unlock`,
        `x-csrf-token: ${csrfSecret}`,
        `cookie=${csrfSecret}`,
        `download=/api/save?native_save_token=${nativeSecret}`,
        `repo=${repoRoot}`,
        `temp=${tempRoot}`,
        `windows=${windowsPath}`,
        `linux=${linuxPath}`,
    ].join('\n');

    const redacted = redactSensitive(input, {
        token: launchSecret,
        csrf: csrfSecret,
        secrets: [nativeSecret],
        repoRoot,
        dataRoot: tempRoot,
    });

    assert.ok(!redacted.includes(launchSecret));
    assert.ok(!redacted.includes(csrfSecret));
    assert.ok(!redacted.includes(nativeSecret));
    assert.ok(!redacted.includes(repoRoot));
    assert.ok(!redacted.includes(tempRoot));
    assert.ok(!/[A-Za-z]:[\\/]Users[\\/]/i.test(redacted));
    assert.ok(!redacted.includes(linuxPath));
    assert.match(redacted, /token=<redacted>/);
    assert.match(redacted, /x-csrf-token: <redacted>/i);
    assert.match(redacted, /<local-path>/);
});
