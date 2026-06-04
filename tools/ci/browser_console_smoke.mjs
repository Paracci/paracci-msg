#!/usr/bin/env node

import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const SCRIPT_DIR = path.dirname(SCRIPT_PATH);
const DEFAULT_REPO_ROOT = path.resolve(SCRIPT_DIR, '..', '..');
const DEFAULT_TIMEOUT_SECONDS = 90;
const LOOPBACK_HOST = '127.0.0.1';
const RUNTIME_PYTHON = 'python';
const RUNTIME_EXECUTABLE = 'executable';
const RUNTIME_PORTABLE_ZIP = 'portable-zip';
const SUPPORTED_RUNTIMES = new Set([RUNTIME_PYTHON, RUNTIME_EXECUTABLE, RUNTIME_PORTABLE_ZIP]);

export class SmokeFailure extends Error {
    constructor(message) {
        super(message);
        this.name = 'SmokeFailure';
    }
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function escapeRegExp(value) {
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function replaceExactSecret(text, secret) {
    if (!secret || typeof secret !== 'string') return text;
    return text.split(secret).join('<redacted>');
}

export function redactSensitive(value, options = {}) {
    let text = String(value ?? '');
    const secrets = [
        options.token,
        options.csrf,
        ...(Array.isArray(options.secrets) ? options.secrets : []),
    ].filter(secret => typeof secret === 'string' && secret.length >= 8);
    for (const secret of secrets) {
        text = replaceExactSecret(text, secret);
    }

    const roots = [
        options.repoRoot,
        options.dataRoot,
        options.profileRoot,
        options.extractRoot,
        options.executableRoot,
        options.zipRoot,
        options.executable,
        options.zipPath,
        ...(Array.isArray(options.roots) ? options.roots : []),
    ].filter(root => typeof root === 'string' && root.length > 0);
    for (const root of roots.sort((a, b) => b.length - a.length)) {
        text = text.replace(new RegExp(escapeRegExp(root), 'gi'), '<local-path>');
    }

    text = text.replace(
        /([?&](?:token|csrf|csrf_token|preview_token|native_save_token|_paracci_token|_csrf_token)=)[^&\s"'<>]+/gi,
        '$1<redacted>'
    );
    text = text.replace(
        /((?:authorization|cookie|set-cookie|x-csrf-token|x-paracci-token)\s*[:=]\s*)[^\r\n]+/gi,
        '$1<redacted>'
    );
    text = text.replace(
        /(["'](?:authorization|cookie|set-cookie|x-csrf-token|x-paracci-token)["']\s*:\s*["'])[^"']+(["'])/gi,
        '$1<redacted>$2'
    );

    const windowsUserHome = new RegExp(
        String.raw`\b[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s"'<>|]+(?:[\\/][^\\\r\n"'<>|]+)*`,
        'gi'
    );
    const escapedUsersPath = new RegExp(
        String.raw`\\\\+Users\\\\+[^\\\s"'<>|]+(?:\\\\+[^\\\r\n"'<>|]+)*`,
        'gi'
    );
    const macUserHome = new RegExp(
        String.raw`(^|[^A-Za-z0-9_./-])` + '/' + 'Users' + String.raw`/[^/\s"'<>]+(?:/[^\s"'<>]+)*`,
        'g'
    );
    const linuxUserHome = new RegExp(
        String.raw`(^|[^A-Za-z0-9_./-])` + '/' + 'home' + String.raw`/[^/\s"'<>]+(?:/[^\s"'<>]+)*`,
        'g'
    );
    const windowsDrivePath = new RegExp(
        String.raw`\b[A-Za-z]:[\\/]+[^\\/\s"'<>|]+(?:[\\/][^\\\r\n"'<>|]+)*`,
        'g'
    );
    const posixTempPath = new RegExp(
        String.raw`(^|[^A-Za-z0-9_./-])` + '/' + String.raw`(?:tmp|private/var/folders|var/folders)/[^\s"'<>]+`,
        'g'
    );
    text = text.replace(windowsUserHome, '<local-path>');
    text = text.replace(escapedUsersPath, '<local-path>');
    text = text.replace(macUserHome, '$1<local-path>');
    text = text.replace(linuxUserHome, '$1<local-path>');
    text = text.replace(windowsDrivePath, '<local-path>');
    text = text.replace(posixTempPath, '$1<local-path>');
    return text;
}

export function parseBootstrapEntrypoint(text, expectedPort = null) {
    const match = String(text ?? '').match(/http:\/\/127\.0\.0\.1:\d+\/__paracci_bootstrap\?[^\s]+/);
    if (!match) return null;

    let entrypoint;
    try {
        entrypoint = new URL(match[0]);
    } catch (error) {
        throw new SmokeFailure(`Runtime printed an invalid authenticated entrypoint: ${error.message}`);
    }

    const token = entrypoint.searchParams.get('token') || '';
    if (
        entrypoint.protocol !== 'http:'
        || entrypoint.hostname !== LOOPBACK_HOST
        || entrypoint.pathname !== '/__paracci_bootstrap'
        || !token
    ) {
        throw new SmokeFailure('Runtime printed an invalid authenticated entrypoint.');
    }

    if (expectedPort !== null && String(entrypoint.port) !== String(expectedPort)) {
        throw new SmokeFailure('Runtime printed an authenticated entrypoint for an unexpected port.');
    }

    return {
        href: entrypoint.href,
        origin: entrypoint.origin,
        port: Number(entrypoint.port),
        token,
        next: entrypoint.searchParams.get('next') || '',
    };
}

export async function reserveLoopbackPort() {
    const server = net.createServer();
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, LOOPBACK_HOST, resolve);
    });
    const address = server.address();
    await new Promise((resolve, reject) => {
        server.close(error => error ? reject(error) : resolve());
    });
    if (!address || typeof address === 'string') {
        throw new SmokeFailure('Could not reserve a loopback port.');
    }
    return Number(address.port);
}

async function waitForPort(port, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        try {
            await new Promise((resolve, reject) => {
                const socket = net.createConnection({ host: LOOPBACK_HOST, port }, () => {
                    socket.end();
                    resolve();
                });
                socket.once('error', reject);
                socket.setTimeout(1000, () => {
                    socket.destroy(new Error('timed out waiting for loopback listener'));
                });
            });
            return;
        } catch {
            await delay(100);
        }
    }
    throw new SmokeFailure('Timed out waiting for Paracci to listen on loopback.');
}

async function waitForBootstrapEntrypoint(proc, output, port, timeoutMs, runtimeLabel) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (output.spawnError) {
            throw new SmokeFailure(`${runtimeLabel} process failed to start: ${formatError(output.spawnError)}`);
        }
        if (proc.exitCode !== null) {
            throw new SmokeFailure(`${runtimeLabel} exited early with code ${proc.exitCode}.`);
        }
        const entrypoint = parseBootstrapEntrypoint(output.text, port);
        if (entrypoint) return entrypoint;
        await delay(100);
    }
    throw new SmokeFailure('Timed out waiting for Paracci authenticated entrypoint.');
}

function formatError(error) {
    if (!error) return '<unknown error>';
    if (error.stack) return error.stack;
    if (error.message) return error.message;
    return String(error);
}

function outputTail(output, redaction) {
    return redactSensitive(output.text.slice(-4000), redaction);
}

function failureMessage(message, details) {
    const parts = [redactSensitive(message, details.redaction)];
    if (details.browserFailures.length > 0) {
        parts.push(
            '--- browser failures ---',
            ...details.browserFailures.map(item => redactSensitive(item, details.redaction))
        );
    }
    if (details.output.text) {
        parts.push(`--- ${details.runtimeLabel || 'runtime'} output ---`, outputTail(details.output, details.redaction));
    }
    return parts.join('\n');
}

function addOutputCollector(stream, output) {
    if (!stream) return;
    stream.setEncoding('utf8');
    stream.on('data', chunk => {
        output.text += chunk;
        if (output.text.length > 100000) {
            output.text = output.text.slice(-100000);
        }
    });
}

async function stopProcess(proc) {
    if (!proc || proc.exitCode !== null) return;
    proc.kill();
    const stopped = await Promise.race([
        new Promise(resolve => proc.once('exit', () => resolve(true))),
        delay(10000).then(() => false),
    ]);
    if (!stopped && proc.exitCode === null) {
        proc.kill('SIGKILL');
        await Promise.race([
            new Promise(resolve => proc.once('exit', resolve)),
            delay(5000),
        ]);
    }
}

function isSameOrigin(urlText, origin) {
    try {
        return new URL(urlText).origin === origin;
    } catch {
        return false;
    }
}

function isRelevantAppResource(urlText, resourceType) {
    let parsed;
    try {
        parsed = new URL(urlText);
    } catch {
        return false;
    }
    return (
        parsed.pathname === '/favicon.ico'
        || parsed.pathname.startsWith('/static/')
        || parsed.pathname.startsWith('/api/')
        || ['document', 'script', 'stylesheet', 'font'].includes(resourceType)
    );
}

function buildRuntimeEnv(dataDir, options = {}) {
    const env = { ...process.env };
    delete env.PARACCI_LOOPBACK_TOKEN;
    if (options.usePortableData) {
        delete env.DATA_DIR;
    } else {
        env.DATA_DIR = dataDir;
    }
    env.PARACCI_NO_GUI = '1';
    env.PYOQS_VERSION = env.PYOQS_VERSION || 'paracci-browser-smoke-no-autoinstall';
    env.QT_QPA_PLATFORM = env.QT_QPA_PLATFORM || 'offscreen';
    if (options.scrubPackagedEnv) {
        for (const name of ['OQS_INSTALL_PATH', 'LIBOQS_LIB_DIR', 'LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH']) {
            delete env[name];
        }
        if (env.PATH) {
            env.PATH = env.PATH
                .split(path.delimiter)
                .filter(item => !item.toLowerCase().includes('_oqs') && !item.toLowerCase().includes('liboqs'))
                .join(path.delimiter);
        }
    }
    return env;
}

function defaultExecutable(repoRoot) {
    return path.join(repoRoot, 'builds', 'windows', 'Paracci', 'Paracci.exe');
}

function resolveOptionalPath(value) {
    return value ? path.resolve(String(value)) : '';
}

export function normalizeSmokeOptions(options = {}) {
    const repoRoot = path.resolve(options.repoRoot || DEFAULT_REPO_ROOT);
    const requestedRuntime = options.runtime
        || (options.zip || options.zipPath ? RUNTIME_PORTABLE_ZIP : null)
        || (options.executable ? RUNTIME_EXECUTABLE : RUNTIME_PYTHON);
    const runtime = String(requestedRuntime);
    if (!SUPPORTED_RUNTIMES.has(runtime)) {
        throw new SmokeFailure(`Unsupported runtime: ${runtime}`);
    }

    const timeoutSeconds = Number(options.timeoutSeconds ?? DEFAULT_TIMEOUT_SECONDS);
    if (!Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0) {
        throw new SmokeFailure('--timeout-seconds must be a positive number.');
    }

    const python = options.python || defaultPython();
    if (!python) throw new SmokeFailure('--python must not be empty.');

    const executable = runtime === RUNTIME_EXECUTABLE
        ? resolveOptionalPath(options.executable || defaultExecutable(repoRoot))
        : resolveOptionalPath(options.executable);
    const zipPath = runtime === RUNTIME_PORTABLE_ZIP
        ? resolveOptionalPath(options.zipPath || options.zip)
        : resolveOptionalPath(options.zipPath || options.zip);

    if (runtime === RUNTIME_EXECUTABLE && !executable) {
        throw new SmokeFailure('--executable must not be empty for executable runtime.');
    }
    if (runtime === RUNTIME_PORTABLE_ZIP && !zipPath) {
        throw new SmokeFailure('--zip must be provided for portable-zip runtime.');
    }

    const port = options.port === undefined || options.port === null ? null : Number(options.port);
    if (port !== null && (!Number.isInteger(port) || port <= 0 || port > 65535)) {
        throw new SmokeFailure('--port must be a valid TCP port.');
    }

    return {
        runtime,
        python,
        repoRoot,
        timeoutSeconds,
        port,
        executable,
        zipPath,
        help: Boolean(options.help),
    };
}

async function assertFile(filePath, description) {
    let stats;
    try {
        stats = await fs.stat(filePath);
    } catch {
        throw new SmokeFailure(`${description} not found: ${filePath}`);
    }
    if (!stats.isFile()) {
        throw new SmokeFailure(`${description} is not a file: ${filePath}`);
    }
    if (stats.size <= 0) {
        throw new SmokeFailure(`${description} is empty: ${filePath}`);
    }
}

export async function validateRuntimeInputs(options = {}) {
    const config = normalizeSmokeOptions(options);
    if (config.runtime === RUNTIME_PYTHON) {
        await assertFile(path.join(config.repoRoot, 'run.py'), 'Paracci Python launcher');
    } else if (config.runtime === RUNTIME_EXECUTABLE) {
        await assertFile(config.executable, 'Packaged executable');
    } else if (config.runtime === RUNTIME_PORTABLE_ZIP) {
        await assertFile(config.zipPath, 'Windows portable ZIP');
        await assertFile(
            path.join(config.repoRoot, 'tools', 'ci', 'release_artifact_validation.py'),
            'Release artifact validation helper'
        );
    }
    return config;
}

function spawnRuntime(command, args, { cwd, env, output, browserFailures, runtimeLabel }) {
    const proc = spawn(command, args, {
        cwd,
        env,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
    });
    addOutputCollector(proc.stdout, output);
    addOutputCollector(proc.stderr, output);
    proc.once('error', error => {
        output.spawnError = error;
        browserFailures.push(`${runtimeLabel} process error: ${formatError(error)}`);
    });
    return proc;
}

async function collectProcessOutput(proc) {
    let stdout = '';
    let stderr = '';
    if (proc.stdout) {
        proc.stdout.setEncoding('utf8');
        proc.stdout.on('data', chunk => {
            stdout += chunk;
        });
    }
    if (proc.stderr) {
        proc.stderr.setEncoding('utf8');
        proc.stderr.on('data', chunk => {
            stderr += chunk;
        });
    }
    const exitCode = await new Promise(resolve => {
        proc.once('error', error => {
            stderr += formatError(error);
            resolve(1);
        });
        proc.once('close', code => resolve(code ?? 0));
    });
    return { exitCode, stdout, stderr };
}

async function extractPortableZip(config, extractRoot, redaction) {
    await fs.mkdir(extractRoot, { recursive: true });
    const helper = path.join(config.repoRoot, 'tools', 'ci', 'release_artifact_validation.py');
    const proc = spawn(
        config.python,
        [
            helper,
            'extract-windows-portable-zip',
            '--zip',
            config.zipPath,
            '--destination',
            extractRoot,
        ],
        {
            cwd: config.repoRoot,
            stdio: ['ignore', 'pipe', 'pipe'],
            windowsHide: true,
        }
    );
    const result = await collectProcessOutput(proc);
    const combined = `${result.stdout || ''}${result.stderr || ''}`;
    if (result.exitCode !== 0) {
        throw new SmokeFailure(`Portable ZIP extraction failed.\n${combined}`);
    }
    const executable = result.stdout.trim().split(/\r?\n/).filter(Boolean).pop();
    if (!executable) {
        throw new SmokeFailure('Portable ZIP extraction did not report a packaged executable.');
    }
    const resolved = path.resolve(executable);
    redaction.roots.push(resolved, path.dirname(resolved));
    return resolved;
}

async function startRuntime(config, tempRoot, port, output, browserFailures, redaction) {
    if (config.runtime === RUNTIME_PYTHON) {
        const dataDir = path.join(tempRoot, 'data');
        redaction.roots.push(dataDir);
        return {
            runtimeLabel: 'Python runtime',
            proc: spawnRuntime(
                config.python,
                [path.join(config.repoRoot, 'run.py'), '--no-gui', '--port', String(port)],
                {
                    cwd: config.repoRoot,
                    env: buildRuntimeEnv(dataDir),
                    output,
                    browserFailures,
                    runtimeLabel: 'Python runtime',
                }
            ),
        };
    }

    if (config.runtime === RUNTIME_EXECUTABLE) {
        const dataDir = path.join(tempRoot, 'data');
        redaction.executable = config.executable;
        redaction.executableRoot = path.dirname(config.executable);
        redaction.roots.push(dataDir, config.executable, path.dirname(config.executable));
        return {
            runtimeLabel: 'packaged executable runtime',
            proc: spawnRuntime(
                config.executable,
                ['--no-gui', '--port', String(port)],
                {
                    cwd: path.dirname(config.executable),
                    env: buildRuntimeEnv(dataDir, { scrubPackagedEnv: true }),
                    output,
                    browserFailures,
                    runtimeLabel: 'packaged executable runtime',
                }
            ),
        };
    }

    const extractRoot = path.join(tempRoot, 'portable-extract');
    redaction.extractRoot = extractRoot;
    redaction.zipPath = config.zipPath;
    redaction.zipRoot = path.dirname(config.zipPath);
    redaction.roots.push(extractRoot, config.zipPath, path.dirname(config.zipPath));
    const executable = await extractPortableZip(config, extractRoot, redaction);
    const portableRoot = path.dirname(executable);
    const portableDataDir = path.join(portableRoot, 'data');
    redaction.executable = executable;
    redaction.executableRoot = portableRoot;
    redaction.roots.push(portableRoot, portableDataDir);
    return {
        runtimeLabel: 'portable ZIP runtime',
        proc: spawnRuntime(
            executable,
            ['--no-gui', '--port', String(port)],
            {
                cwd: portableRoot,
                env: buildRuntimeEnv(portableDataDir, { scrubPackagedEnv: true, usePortableData: true }),
                output,
                browserFailures,
                runtimeLabel: 'portable ZIP runtime',
            }
        ),
    };
}

export async function runBrowserConsoleSmoke(options = {}) {
    const config = await validateRuntimeInputs(options);
    const timeoutMs = Math.max(1, Number(config.timeoutSeconds)) * 1000;
    const port = config.port || await reserveLoopbackPort();
    const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'paracci-browser-smoke-'));
    const profileRoot = path.join(tempRoot, 'browser-profile');
    const output = { text: '' };
    const browserFailures = [];
    const redaction = {
        repoRoot: config.repoRoot,
        dataRoot: tempRoot,
        profileRoot,
        roots: [tempRoot],
        token: '',
        csrf: '',
        executable: config.executable,
        executableRoot: config.executable ? path.dirname(config.executable) : '',
        zipPath: config.zipPath,
        zipRoot: config.zipPath ? path.dirname(config.zipPath) : '',
    };

    let proc = null;
    let context = null;
    let runtimeLabel = 'runtime';
    try {
        const runtime = await startRuntime(config, tempRoot, port, output, browserFailures, redaction);
        proc = runtime.proc;
        runtimeLabel = runtime.runtimeLabel;

        const entrypoint = await waitForBootstrapEntrypoint(proc, output, port, timeoutMs, runtimeLabel);
        redaction.token = entrypoint.token;
        await waitForPort(port, timeoutMs);

        context = await chromium.launchPersistentContext(profileRoot, {
            headless: true,
            viewport: { width: 1280, height: 900 },
            serviceWorkers: 'allow',
            acceptDownloads: false,
        });
        const page = context.pages()[0] || await context.newPage();

        await page.addInitScript(() => {
            window.addEventListener('unhandledrejection', event => {
                const reason = event.reason;
                const name = reason?.name || '';
                const message = reason?.message || String(reason || 'Unhandled promise rejection');
                // Mirrors paracci/app/static/js/early.js; this browser quirk is not an app failure.
                if (name === 'AbortError' || message === 'Transition was skipped') return;
                console.error(`[ParacciSmokeUnhandledRejection] ${message}`);
            });
        });

        page.on('pageerror', error => {
            browserFailures.push(`pageerror: ${formatError(error)}`);
        });
        page.on('console', message => {
            if (message.type() !== 'error') return;
            const location = message.location();
            const suffix = location?.url
                ? ` (${location.url}:${location.lineNumber}:${location.columnNumber})`
                : '';
            browserFailures.push(`console.error: ${message.text()}${suffix}`);
        });
        page.on('response', response => {
            if (!isSameOrigin(response.url(), entrypoint.origin)) return;
            if (response.status() < 400) return;
            const resourceType = response.request().resourceType();
            if (!isRelevantAppResource(response.url(), resourceType)) return;
            browserFailures.push(
                `http ${response.status()}: ${response.request().method()} ${response.url()} [${resourceType}]`
            );
        });
        page.on('requestfailed', request => {
            if (!isSameOrigin(request.url(), entrypoint.origin)) return;
            const resourceType = request.resourceType();
            const failure = request.failure()?.errorText || 'request failed';
            if (request.isNavigationRequest() && failure.includes('net::ERR_ABORTED')) return;
            if (!isRelevantAppResource(request.url(), resourceType)) return;
            browserFailures.push(`request failed: ${request.method()} ${request.url()} [${resourceType}] ${failure}`);
        });

        await page.goto(entrypoint.href, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
        await page.waitForURL(url => new URL(url).pathname === '/unlock', { timeout: Math.min(timeoutMs, 30000) });
        await page.locator('#authForm').waitFor({ state: 'visible', timeout: 10000 });
        await page.locator('#pinInput').waitFor({ state: 'attached', timeout: 10000 });
        await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
        await delay(750);

        const state = await page.evaluate(() => {
            const browserToken = document.querySelector('meta[name="paracci-browser-token"]')?.getAttribute('content') || '';
            const csrf = document.querySelector('meta[name="paracci-csrf-token"]')?.getAttribute('content') || '';
            const bootstrapStatus = document.getElementById('bootstrapStatus')?.textContent || '';
            const authForm = document.getElementById('authForm');
            return {
                pathname: window.location.pathname,
                title: document.title,
                bodyText: document.body?.innerText?.slice(0, 500) || '',
                hasAuthForm: Boolean(authForm),
                authMode: authForm?.dataset?.mode || '',
                hasPinInput: Boolean(document.getElementById('pinInput')),
                browserToken,
                csrf,
                bootstrapStatus,
            };
        });
        redaction.csrf = state.csrf;

        if (state.pathname !== '/unlock') {
            throw new SmokeFailure(`Expected /unlock after bootstrap, got ${state.pathname || '<empty path>'}.`);
        }
        if (state.bootstrapStatus.includes('could not be initialized')) {
            throw new SmokeFailure('Bootstrap authorization reported a fail-closed state.');
        }
        if (!state.hasAuthForm || !state.hasPinInput || state.authMode !== 'init') {
            throw new SmokeFailure(`Unlock/setup page did not render the expected auth DOM. Title: ${state.title}`);
        }
        if (!state.browserToken || state.browserToken !== entrypoint.token) {
            throw new SmokeFailure('Rendered page did not expose the authenticated no-GUI browser token.');
        }
        if (!state.csrf) {
            throw new SmokeFailure('Rendered page did not expose a CSRF token.');
        }
        if (browserFailures.length > 0) {
            throw new SmokeFailure('Unexpected browser console, page, or resource failure.');
        }

        console.log(`Browser console smoke passed (${config.runtime}): ${entrypoint.origin}/unlock`);
    } catch (error) {
        if (error instanceof SmokeFailure) {
            throw new SmokeFailure(failureMessage(error.message, { output, browserFailures, redaction, runtimeLabel }));
        }
        throw new SmokeFailure(
            failureMessage(
                `Browser console smoke failed: ${formatError(error)}`,
                { output, browserFailures, redaction, runtimeLabel }
            )
        );
    } finally {
        if (context) {
            await context.close().catch(() => {});
        }
        await stopProcess(proc);
        await fs.rm(tempRoot, { recursive: true, force: true }).catch(() => {});
    }
}

function defaultPython() {
    return process.env.PARACCI_PYTHON || process.env.PYTHON || 'python';
}

function requireValue(argv, index, flag) {
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) {
        throw new SmokeFailure(`${flag} requires a value.`);
    }
    return value;
}

export function parseArgs(argv) {
    const args = {
        python: defaultPython(),
        repoRoot: DEFAULT_REPO_ROOT,
        timeoutSeconds: DEFAULT_TIMEOUT_SECONDS,
        help: false,
    };
    for (let index = 0; index < argv.length; index += 1) {
        const arg = argv[index];
        if (arg === '--help' || arg === '-h') {
            args.help = true;
        } else if (arg === '--python') {
            args.python = requireValue(argv, index, arg);
            index += 1;
        } else if (arg === '--runtime') {
            args.runtime = requireValue(argv, index, arg);
            index += 1;
        } else if (arg === '--executable') {
            args.executable = requireValue(argv, index, arg);
            index += 1;
        } else if (arg === '--zip') {
            args.zipPath = requireValue(argv, index, arg);
            index += 1;
        } else if (arg === '--repo-root') {
            args.repoRoot = requireValue(argv, index, arg);
            index += 1;
        } else if (arg === '--port') {
            args.port = Number(requireValue(argv, index, arg));
            index += 1;
        } else if (arg === '--timeout-seconds') {
            args.timeoutSeconds = Number(requireValue(argv, index, arg));
            index += 1;
        } else {
            throw new SmokeFailure(`Unknown argument: ${arg}`);
        }
    }
    return normalizeSmokeOptions(args);
}

function printHelp() {
    console.log(`Usage: node tools/ci/browser_console_smoke.mjs [options]

Options:
  --runtime <mode>            Runtime mode: python, executable, or portable-zip. Defaults to python.
  --python <path>             Python executable for source runtime and ZIP extraction helper.
                              Defaults to PARACCI_PYTHON, PYTHON, or python.
  --executable <path>         Packaged executable for --runtime executable.
                              Defaults to builds/windows/Paracci/Paracci.exe in executable mode.
  --zip <path>                Windows portable ZIP for --runtime portable-zip.
  --repo-root <path>          Repository root. Defaults to the parent of tools/ci.
  --port <number>             Fixed loopback port. Defaults to a reserved random port.
  --timeout-seconds <number>  Startup and browser timeout. Defaults to ${DEFAULT_TIMEOUT_SECONDS}.
  -h, --help                  Show this help.`);
}

async function main(argv = process.argv.slice(2)) {
    const args = parseArgs(argv);
    if (args.help) {
        printHelp();
        return 0;
    }
    await runBrowserConsoleSmoke(args);
    return 0;
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (invokedPath === SCRIPT_PATH) {
    main().catch(error => {
        const message = error instanceof SmokeFailure ? error.message : formatError(error);
        console.error(`[ERROR] ${redactSensitive(message)}`);
        process.exitCode = 1;
    });
}
