import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const SESSION_JS = fs.readFileSync(
    path.resolve(TEST_DIR, '../app/static/js/session.js'),
    'utf8'
);

function eventTarget(initial = {}) {
    const listeners = new Map();
    return Object.assign({
        addEventListener(type, handler) {
            if (!listeners.has(type)) listeners.set(type, new Set());
            listeners.get(type).add(handler);
        },
        removeEventListener(type, handler) {
            listeners.get(type)?.delete(handler);
        },
        dispatch(type) {
            for (const handler of Array.from(listeners.get(type) || [])) {
                handler({ type });
            }
        },
        listenerCount(type) {
            return listeners.get(type)?.size || 0;
        }
    }, initial);
}

function makeHarness({
    writeText = async () => {},
    nativeApi = null,
    hasNativeWindow = false,
    resolveNativeWaitImmediately = false
} = {}) {
    let timerId = 0;
    const intervals = new Map();
    const timeouts = new Map();
    const notices = [];
    let focused = true;
    const button = { disabled: false, style: {}, textContent: '' };

    const document = eventTarget({
        visibilityState: 'visible',
        hasFocus: () => focused,
        getElementById: id => id === 'btn-copy-msg' ? button : null,
        querySelectorAll: () => []
    });
    const window = eventTarget({
        PARACCI_I18N: {
            clipboard_cleared: 'Clipboard cleared.',
            clipboard_clear_failed: 'Clipboard clear failed.',
            clipboard_browser_history_warning: 'Browser history warning.',
            text_copied_notify: 'Text copied.',
            clearing_clipboard: 'Clearing ({s})',
            copy_protection_btn: 'Copy'
        },
        pywebview: nativeApi ? { api: nativeApi } : undefined
    });
    const setTimeout = (handler, delay) => {
        const id = ++timerId;
        if (resolveNativeWaitImmediately && delay === 100) {
            Promise.resolve().then(handler);
        } else {
            timeouts.set(id, { handler, delay });
        }
        return id;
    };
    const sandbox = {
        window,
        document,
        navigator: { clipboard: { writeText } },
        localStorage: { getItem: () => null, setItem: () => {} },
        fetch: async () => ({
            ok: true,
            json: async () => ({ has_native_window: hasNativeWindow })
        }),
        console: { error: () => {}, warn: () => {}, log: () => {} },
        showNotification: (message, type = 'info') => notices.push({ message, type }),
        setInterval(handler) {
            const id = ++timerId;
            intervals.set(id, handler);
            return id;
        },
        clearInterval(id) {
            intervals.delete(id);
        },
        setTimeout,
        clearTimeout(id) {
            timeouts.delete(id);
        },
        marked: { parse: value => value },
        HTMLButtonElement: class HTMLButtonElement {}
    };
    vm.createContext(sandbox);
    vm.runInContext(SESSION_JS, sandbox, { filename: 'session.js' });
    vm.runInContext("currentMsgRawText = 'secret'; window._currentMsgCanCopy = true;", sandbox);

    async function flush() {
        for (let index = 0; index < 8; index += 1) {
            await Promise.resolve();
        }
    }

    return {
        window,
        document,
        notices,
        button,
        setFocused(value) {
            focused = value;
            document.visibilityState = value ? 'visible' : 'hidden';
        },
        async copy() {
            await window.handleSecureCopy();
            await flush();
        },
        async elapseCountdown() {
            for (let tick = 0; tick < 30; tick += 1) {
                for (const handler of Array.from(intervals.values())) handler();
                await flush();
            }
        },
        async fireTimeout(delay) {
            const match = Array.from(timeouts.entries()).find(([, entry]) => entry.delay === delay);
            assert.ok(match, `expected timeout for ${delay}ms`);
            timeouts.delete(match[0]);
            match[1].handler();
            await flush();
        }
    };
}

test('browser fallback performs an actual timed clear', async () => {
    const writes = [];
    const harness = makeHarness({
        writeText: async text => writes.push(text)
    });

    await harness.copy();
    await harness.elapseCountdown();

    assert.deepEqual(writes, ['secret', '']);
    assert.ok(harness.notices.some(notice => notice.message === 'Clipboard cleared.'));
    assert.ok(harness.notices.some(notice => notice.message === 'Browser history warning.'));
});

test('browser clear retries once when focus returns', async () => {
    const writes = [];
    let firstClear = true;
    const harness = makeHarness({
        writeText: async text => {
            writes.push(text);
            if (text === '' && firstClear) {
                firstClear = false;
                const error = new Error('Document is not focused');
                error.name = 'NotAllowedError';
                throw error;
            }
        }
    });

    await harness.copy();
    harness.setFocused(false);
    await harness.elapseCountdown();
    assert.equal(harness.window.listenerCount('focus'), 1);

    harness.setFocused(true);
    harness.window.dispatch('focus');
    await new Promise(resolve => setImmediate(resolve));

    assert.deepEqual(writes, ['secret', '', '']);
    assert.equal(harness.window.listenerCount('focus'), 0);
    assert.ok(harness.notices.some(notice => notice.message === 'Clipboard cleared.'));
});

test('browser clear retry expires and reports failure', async () => {
    const writes = [];
    const harness = makeHarness({
        writeText: async text => {
            writes.push(text);
            if (text === '') throw new Error('Document is not focused');
        }
    });

    await harness.copy();
    harness.setFocused(false);
    await harness.elapseCountdown();
    await harness.fireTimeout(30000);

    assert.deepEqual(writes, ['secret', '']);
    assert.equal(harness.window.listenerCount('focus'), 0);
    assert.ok(harness.notices.some(notice => notice.message === 'Clipboard clear failed.'));
    assert.ok(!harness.notices.some(notice => notice.message === 'Clipboard cleared.'));
});

test('native clipboard bridge is preferred for copy and timed clear', async () => {
    const nativeCalls = [];
    const harness = makeHarness({
        writeText: async () => assert.fail('browser clipboard fallback used'),
        nativeApi: {
            copy_and_clear: async (...args) => {
                nativeCalls.push(args);
                return true;
            }
        }
    });

    await harness.copy();
    await harness.elapseCountdown();

    assert.deepEqual(nativeCalls, [['secret', 30], ['', 0]]);
    assert.ok(!harness.notices.some(notice => notice.message === 'Browser history warning.'));
});

test('native-capable shell does not downgrade to browser clipboard before API injection', async () => {
    const writes = [];
    const harness = makeHarness({
        writeText: async text => writes.push(text),
        hasNativeWindow: true,
        resolveNativeWaitImmediately: true
    });

    await harness.copy();

    assert.deepEqual(writes, []);
    assert.ok(harness.notices.some(notice => notice.type === 'error'));
});
