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
    text = text.replace(windowsUserHome, '<local-path>');
    text = text.replace(escapedUsersPath, '<local-path>');
    text = text.replace(macUserHome, '$1<local-path>');
    text = text.replace(linuxUserHome, '$1<local-path>');
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

async function waitForBootstrapEntrypoint(proc, output, port, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (proc.exitCode !== null) {
            throw new SmokeFailure(`Paracci exited early with code ${proc.exitCode}.`);
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
        parts.push('--- python runtime output ---', outputTail(details.output, details.redaction));
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

function buildRuntimeEnv(dataDir) {
    const env = { ...process.env };
    delete env.PARACCI_LOOPBACK_TOKEN;
    env.DATA_DIR = dataDir;
    env.PARACCI_NO_GUI = '1';
    env.PYOQS_VERSION = env.PYOQS_VERSION || 'paracci-browser-smoke-no-autoinstall';
    env.QT_QPA_PLATFORM = env.QT_QPA_PLATFORM || 'offscreen';
    return env;
}

export async function runBrowserConsoleSmoke(options = {}) {
    const repoRoot = path.resolve(options.repoRoot || DEFAULT_REPO_ROOT);
    const python = options.python || process.env.PARACCI_PYTHON || process.env.PYTHON || 'python';
    const timeoutMs = Math.max(1, Number(options.timeoutSeconds || DEFAULT_TIMEOUT_SECONDS)) * 1000;
    const port = options.port || await reserveLoopbackPort();
    const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'paracci-browser-smoke-'));
    const dataDir = path.join(tempRoot, 'data');
    const profileRoot = path.join(tempRoot, 'browser-profile');
    const output = { text: '' };
    const browserFailures = [];
    const redaction = {
        repoRoot,
        dataRoot: tempRoot,
        profileRoot,
        roots: [dataDir],
        token: '',
        csrf: '',
    };

    let proc = null;
    let context = null;
    try {
        proc = spawn(
            python,
            [path.join(repoRoot, 'run.py'), '--no-gui', '--port', String(port)],
            {
                cwd: repoRoot,
                env: buildRuntimeEnv(dataDir),
                stdio: ['ignore', 'pipe', 'pipe'],
                windowsHide: true,
            }
        );
        addOutputCollector(proc.stdout, output);
        addOutputCollector(proc.stderr, output);

        proc.once('error', error => {
            browserFailures.push(`python process error: ${formatError(error)}`);
        });

        const entrypoint = await waitForBootstrapEntrypoint(proc, output, port, timeoutMs);
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

        console.log(`Browser console smoke passed: ${entrypoint.origin}/unlock`);
    } catch (error) {
        if (error instanceof SmokeFailure) {
            throw new SmokeFailure(failureMessage(error.message, { output, browserFailures, redaction }));
        }
        throw new SmokeFailure(
            failureMessage(`Browser console smoke failed: ${formatError(error)}`, { output, browserFailures, redaction })
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

function parseArgs(argv) {
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
            args.python = argv[++index];
        } else if (arg === '--repo-root') {
            args.repoRoot = argv[++index];
        } else if (arg === '--timeout-seconds') {
            args.timeoutSeconds = Number(argv[++index]);
        } else {
            throw new SmokeFailure(`Unknown argument: ${arg}`);
        }
    }
    if (!args.python) throw new SmokeFailure('--python must not be empty.');
    if (!Number.isFinite(args.timeoutSeconds) || args.timeoutSeconds <= 0) {
        throw new SmokeFailure('--timeout-seconds must be a positive number.');
    }
    return args;
}

function printHelp() {
    console.log(`Usage: node tools/ci/browser_console_smoke.mjs [options]

Options:
  --python <path>             Python executable. Defaults to PARACCI_PYTHON, PYTHON, or python.
  --repo-root <path>          Repository root. Defaults to the parent of tools/ci.
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
