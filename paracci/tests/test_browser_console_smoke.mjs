import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
    assertNoPackagedVenvBootstrapOutput,
    parseBootstrapEntrypoint,
    parseArgs,
    redactSensitive,
    SmokeFailure,
    validateRuntimeInputs,
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
    const extractRoot = path.join(tempRoot, 'portable-extract');
    const executablePath = path.join(repoRoot, 'builds', 'windows', 'Paracci', 'Paracci.exe');
    const zipPath = path.join(repoRoot, 'builds', 'windows', 'Paracci-Portable-v1.6.0.zip');
    const windowsPath = ['C:', 'Users', 'private-user', 'Desktop', 'paracci-msg'].join('\\');
    const ciDrivePath = ['D:', 'a', 'paracci-msg', 'paracci-msg', 'release-assets'].join('\\');
    const linuxPath = ['', 'home', 'private-user', '.cache', 'paracci-smoke'].join('/');
    const input = [
        `url=http://127.0.0.1:54321/__paracci_bootstrap?token=${launchSecret}&next=/unlock`,
        `x-csrf-token: ${csrfSecret}`,
        `cookie=${csrfSecret}`,
        `download=/api/save?native_save_token=${nativeSecret}`,
        `repo=${repoRoot}`,
        `temp=${tempRoot}`,
        `extract=${extractRoot}`,
        `executable=${executablePath}`,
        `zip=${zipPath}`,
        `windows=${windowsPath}`,
        `ci=${ciDrivePath}`,
        `linux=${linuxPath}`,
    ].join('\n');

    const redacted = redactSensitive(input, {
        token: launchSecret,
        csrf: csrfSecret,
        secrets: [nativeSecret],
        repoRoot,
        dataRoot: tempRoot,
        extractRoot,
        executable: executablePath,
        zipPath,
    });

    assert.ok(!redacted.includes(launchSecret));
    assert.ok(!redacted.includes(csrfSecret));
    assert.ok(!redacted.includes(nativeSecret));
    assert.ok(!redacted.includes(repoRoot));
    assert.ok(!redacted.includes(tempRoot));
    assert.ok(!redacted.includes(extractRoot));
    assert.ok(!redacted.includes(executablePath));
    assert.ok(!redacted.includes(zipPath));
    assert.ok(!/[A-Za-z]:[\\/]Users[\\/]/i.test(redacted));
    assert.ok(!redacted.includes(ciDrivePath));
    assert.ok(!redacted.includes(linuxPath));
    assert.match(redacted, /token=<redacted>/);
    assert.match(redacted, /x-csrf-token: <redacted>/i);
    assert.match(redacted, /<local-path>/);
});

test('parseArgs preserves the default Python runtime command shape', () => {
    const parsed = parseArgs(['--python', 'custom-python', '--timeout-seconds', '12']);

    assert.equal(parsed.runtime, 'python');
    assert.equal(parsed.python, 'custom-python');
    assert.equal(parsed.timeoutSeconds, 12);
    assert.equal(parsed.repoRoot, REPO_ROOT);
});

test('parseArgs accepts packaged executable runtime arguments', () => {
    const executable = path.join('builds', 'windows', 'Paracci', 'Paracci.exe');
    const parsed = parseArgs(['--runtime', 'executable', '--executable', executable]);

    assert.equal(parsed.runtime, 'executable');
    assert.equal(parsed.executable, path.resolve(executable));
});

test('parseArgs accepts portable ZIP runtime arguments', () => {
    const zipPath = path.join('builds', 'windows', 'Paracci-Portable-v1.6.0.zip');
    const parsed = parseArgs(['--runtime', 'portable-zip', '--zip', zipPath]);

    assert.equal(parsed.runtime, 'portable-zip');
    assert.equal(parsed.zipPath, path.resolve(zipPath));
});

test('packaged runtimes reject source virtualenv bootstrap output', () => {
    const output = '[*] Virtual environment (.venv) not found. Creating a new virtual environment...';

    assert.throws(
        () => assertNoPackagedVenvBootstrapOutput('executable', output),
        /source virtual environment bootstrap/
    );
    assert.throws(
        () => assertNoPackagedVenvBootstrapOutput('portable-zip', '[*] Re-running script inside virtual environment: <local-path>'),
        /source virtual environment bootstrap/
    );
});

test('python runtime allows source virtualenv bootstrap output', () => {
    const output = '[*] Virtual environment (.venv) not found. Creating a new virtual environment...';

    assert.doesNotThrow(() => assertNoPackagedVenvBootstrapOutput('python', output));
});

test('packaged runtime input validation fails clearly for missing executable', async () => {
    const missing = path.join(TEST_DIR, 'missing-packaged-app.exe');

    await assert.rejects(
        () => validateRuntimeInputs({ runtime: 'executable', executable: missing, repoRoot: REPO_ROOT }),
        /Packaged executable not found/
    );
});

test('portable ZIP input validation fails clearly for missing archive', async () => {
    const missing = path.join(TEST_DIR, 'missing-portable.zip');

    await assert.rejects(
        () => validateRuntimeInputs({ runtime: 'portable-zip', zipPath: missing, repoRoot: REPO_ROOT }),
        /Windows portable ZIP not found/
    );
});
