import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    parseBootstrapEntrypoint,
    redactSensitive,
} from '../ci/browser_console_smoke.mjs';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(SCRIPT_DIR, '..', '..');
const MARKER_NAME = '.paracci-e2e-root';
const MARKER_VALUE = 'paracci-e2e-v1';
const ROOT_PREFIX = 'paracci-e2e-';
const STARTUP_TIMEOUT_MS = 90_000;
const PROVISION_TIMEOUT_MS = 120_000;

function delay(milliseconds) {
    return new Promise(resolve => setTimeout(resolve, milliseconds));
}

async function isFile(filePath) {
    try {
        return (await fs.stat(filePath)).isFile();
    } catch {
        return false;
    }
}

async function resolvePython() {
    const configured = process.env.PARACCI_E2E_PYTHON || process.env.PARACCI_PYTHON;
    if (configured) return configured;

    const candidates = process.platform === 'win32'
        ? [path.join(REPO_ROOT, '.venv', 'Scripts', 'python.exe')]
        : [path.join(REPO_ROOT, '.venv', 'bin', 'python')];
    for (const candidate of candidates) {
        if (await isFile(candidate)) return candidate;
    }
    return process.env.PYTHON || 'python';
}

async function assertFrontendAssets() {
    const assetRoot = path.join(REPO_ROOT, 'paracci', 'app', 'static', 'js', 'lib');
    const required = ['purify.min.js', 'marked.min.js', 'highlight.min.js'];
    const missing = [];
    for (const name of required) {
        if (!await isFile(path.join(assetRoot, name))) missing.push(name);
    }
    if (missing.length > 0) {
        throw new Error('Compiled frontend assets are missing. Run npm run build before E2E tests.');
    }
}

function collectStream(stream, output) {
    if (!stream) return;
    stream.setEncoding('utf8');
    stream.on('data', chunk => {
        output.text += chunk;
        if (output.text.length > 100_000) {
            output.text = output.text.slice(-100_000);
        }
    });
}

async function waitForExit(proc, timeoutMs) {
    if (!proc || proc.exitCode !== null) return true;
    return Promise.race([
        new Promise(resolve => proc.once('exit', () => resolve(true))),
        delay(timeoutMs).then(() => false),
    ]);
}

export async function stopProcess(proc) {
    if (!proc || proc.exitCode !== null) return;
    proc.kill();
    if (await waitForExit(proc, 10_000)) return;
    proc.kill('SIGKILL');
    await waitForExit(proc, 5_000);
}

async function runProvisioner(python, root, passphrase) {
    const script = path.join(REPO_ROOT, 'tools', 'e2e', 'provision_profiles.py');
    const proc = spawn(python, [script, '--root', root], {
        cwd: REPO_ROOT,
        env: { ...process.env, PYTHONUNBUFFERED: '1' },
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    proc.stdout.setEncoding('utf8');
    proc.stderr.setEncoding('utf8');
    proc.stdout.on('data', chunk => {
        stdout += chunk;
    });
    proc.stderr.on('data', chunk => {
        stderr += chunk;
    });
    proc.stdin.end(`${passphrase}\n`);

    const exitCodePromise = new Promise((resolve, reject) => {
        proc.once('error', reject);
        proc.once('close', code => resolve(code ?? 1));
    });
    const exitCode = await Promise.race([
        exitCodePromise,
        delay(PROVISION_TIMEOUT_MS).then(() => null),
    ]);
    if (exitCode === null) {
        await stopProcess(proc);
        throw new Error('E2E profile provisioning timed out.');
    }
    if (exitCode !== 0) {
        throw new Error(redactSensitive(stderr || 'E2E profile provisioning failed.', { roots: [root] }));
    }

    let result;
    try {
        result = JSON.parse(stdout);
    } catch {
        throw new Error('E2E profile provisioner returned invalid output.');
    }
    if (JSON.stringify(result.profiles) !== JSON.stringify(['x', 'y'])) {
        throw new Error('E2E profile provisioner returned an unexpected profile set.');
    }
    return result;
}

function assertSafeProfileRoot(root) {
    const resolved = path.resolve(root);
    const tempRoot = path.resolve(os.tmpdir());
    const relative = path.relative(tempRoot, resolved);
    if (
        relative.startsWith('..')
        || path.isAbsolute(relative)
        || !path.basename(resolved).startsWith(ROOT_PREFIX)
    ) {
        throw new Error('Refusing to use an unsafe E2E profile root.');
    }
    return resolved;
}

async function resolveProvisionedFile(root, relativePath) {
    if (!relativePath || path.isAbsolute(relativePath)) {
        throw new Error('E2E provisioner returned an invalid fixture path.');
    }
    const resolved = path.resolve(root, relativePath);
    const relative = path.relative(root, resolved);
    if (relative.startsWith('..') || path.isAbsolute(relative) || !await isFile(resolved)) {
        throw new Error('E2E provisioner returned an unsafe fixture path.');
    }
    return resolved;
}

export async function createProfileSet() {
    const python = await resolvePython();
    const root = assertSafeProfileRoot(
        await fs.mkdtemp(path.join(os.tmpdir(), ROOT_PREFIX))
    );
    await fs.writeFile(path.join(root, MARKER_NAME), `${MARKER_VALUE}\n`, {
        encoding: 'ascii',
        mode: 0o600,
    });
    const passphrase = randomBytes(24).toString('base64url');

    let provisioned;
    try {
        provisioned = await runProvisioner(python, root, passphrase);
    } catch (error) {
        await cleanupProfileSet({ root }).catch(() => {});
        throw error;
    }

    try {
        return {
            root,
            python,
            passphrase,
            dataX: path.join(root, 'data_x'),
            dataY: path.join(root, 'data_y'),
            covers: {
                large: await resolveProvisionedFile(root, provisioned.covers?.large),
                tiny: await resolveProvisionedFile(root, provisioned.covers?.tiny),
            },
        };
    } catch (error) {
        await cleanupProfileSet({ root }).catch(() => {});
        throw error;
    }
}

export async function cleanupProfileSet(profileSet) {
    const root = assertSafeProfileRoot(profileSet.root);
    const marker = path.join(root, MARKER_NAME);
    if (
        !await isFile(marker)
        || (await fs.readFile(marker, 'ascii')).trim() !== MARKER_VALUE
    ) {
        throw new Error('Refusing to remove an unmarked E2E profile root.');
    }
    await fs.rm(root, { recursive: true, force: true });
}

export async function startSourceRuntime(profileSet, dataDir = profileSet.dataX) {
    await assertFrontendAssets();
    const output = { text: '', spawnError: null };
    const env = { ...process.env };
    delete env.PARACCI_LOOPBACK_TOKEN;
    env.DATA_DIR = path.resolve(dataDir);
    env.PARACCI_NO_GUI = '1';
    env.PYTHONUNBUFFERED = '1';
    env.PYOQS_VERSION = env.PYOQS_VERSION || 'paracci-e2e-no-autoinstall';
    env.QT_QPA_PLATFORM = env.QT_QPA_PLATFORM || 'offscreen';

    const proc = spawn(profileSet.python, [path.join(REPO_ROOT, 'run.py'), '--no-gui'], {
        cwd: REPO_ROOT,
        env,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
    });
    collectStream(proc.stdout, output);
    collectStream(proc.stderr, output);
    proc.once('error', error => {
        output.spawnError = error;
    });

    const startupFailure = message => {
        const details = redactSensitive(output.text.slice(-4000), {
            repoRoot: REPO_ROOT,
            dataRoot: profileSet.root,
            roots: [profileSet.root, dataDir],
        });
        return new Error(details ? `${message}\n${details}` : message);
    };

    const deadline = Date.now() + STARTUP_TIMEOUT_MS;
    while (Date.now() < deadline) {
        if (output.spawnError) {
            await stopProcess(proc);
            throw startupFailure('Paracci E2E runtime failed to start.');
        }
        if (proc.exitCode !== null) {
            throw startupFailure(`Paracci E2E runtime exited early with code ${proc.exitCode}.`);
        }
        const entrypoint = parseBootstrapEntrypoint(output.text);
        if (entrypoint) {
            return { proc, output, entrypoint, dataDir: path.resolve(dataDir), profileSet };
        }
        await delay(100);
    }

    await stopProcess(proc);
    throw startupFailure('Timed out waiting for the Paracci E2E bootstrap entrypoint.');
}

export function redactE2EText(runtime, value) {
    return redactSensitive(value, {
        token: runtime.entrypoint?.token,
        repoRoot: REPO_ROOT,
        dataRoot: runtime.profileSet.root,
        roots: [runtime.profileSet.root, runtime.dataDir],
    });
}

export function redactedRuntimeOutput(runtime) {
    return redactE2EText(runtime, runtime.output.text.slice(-4000));
}
