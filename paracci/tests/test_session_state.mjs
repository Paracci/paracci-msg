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

function makeHarness() {
    const navigationCalls = [];
    const elements = new Map();
    function addElement(id, initial) {
        const classes = new Set(initial.classNames || []);
        const attributes = new Map(Object.entries(initial.attributes || {}));
        const element = {
            ...initial,
            classList: {
                add(value) {
                    classes.add(value);
                },
                remove(value) {
                    classes.delete(value);
                },
                contains(value) {
                    return classes.has(value);
                }
            },
            setAttribute(name, value) {
                attributes.set(name, String(value));
            },
            getAttribute(name) {
                return attributes.get(name) ?? null;
            },
            focus() {
                this.focused = true;
            },
            remove() {
                elements.delete(id);
            }
        };
        elements.set(id, element);
        return element;
    }
    addElement('bond-pending-composer', { hidden: false });
    addElement('message-composer', { hidden: true });
    addElement('y-responder-warning', { hidden: false });
    addElement('bonded-checklist', { hidden: true });
    addElement('rendered-message', { textContent: 'opened-message-sentinel' });
    addElement('session-unified-workspace', {
        classNames: ['is-bond-pending'],
        dataset: {
            bondedLabel: 'Bonding active',
            bondedDetail: 'Session ready'
        }
    });
    addElement('session-workspace-status-label', { textContent: 'Bonding pending' });
    addElement('session-workspace-status-detail', { textContent: 'Open first message' });
    addElement('session-create-tab-state', { textContent: 'Bonding pending' });
    const createPanel = addElement('session-create-panel', { hidden: true });
    const openPanel = addElement('session-open-panel', { hidden: false });
    const createTab = addElement('session-action-create', {
        dataset: { sessionActionTab: 'create' },
        attributes: { 'aria-selected': 'false', tabindex: '-1' }
    });
    const openTab = addElement('session-action-open', {
        dataset: { sessionActionTab: 'open' },
        attributes: { 'aria-selected': 'true', tabindex: '0' }
    });
    const document = {
        body: { dataset: { dropAttach: 'false' } },
        addEventListener() {},
        getElementById(id) {
            return elements.get(id) || null;
        },
        querySelectorAll(selector) {
            if (selector === '[data-session-action-tab]') return [createTab, openTab];
            return [];
        }
    };
    const window = {
        addEventListener() {},
        location: {
            assign(value) {
                navigationCalls.push(['assign', value]);
            },
            reload() {
                navigationCalls.push(['reload']);
            }
        }
    };
    const context = vm.createContext({
        Blob,
        clearInterval() {},
        clearTimeout() {},
        console: { error() {}, log() {}, warn() {} },
        document,
        fetch: async () => ({ ok: true, json: async () => ({}) }),
        FormData,
        localStorage: {
            getItem() {
                return null;
            },
            setItem() {}
        },
        navigator: {},
        setInterval() {
            return 1;
        },
        setTimeout() {
            return 1;
        },
        URL,
        window
    });
    vm.runInContext(SESSION_JS, context, { filename: 'session.js' });

    return {
        activateAction: context.activateSessionAction,
        applyState: context.applyPostOpenSessionState,
        document,
        elements,
        navigationCalls,
        tabs: { createTab, openTab },
        panels: { createPanel, openPanel }
    };
}

test('authoritative post-open state unlocks the composer without disturbing the opened message', () => {
    const harness = makeHarness();
    const openedMessage = harness.elements.get('rendered-message');

    harness.applyState({ session_can_send: true });

    assert.equal(harness.elements.has('bond-pending-composer'), false);
    assert.equal(harness.elements.get('message-composer').hidden, false);
    assert.equal(harness.elements.get('y-responder-warning').hidden, true);
    assert.equal(harness.elements.get('bonded-checklist').hidden, false);
    assert.equal(harness.document.body.dataset.dropAttach, 'true');
    assert.equal(openedMessage.textContent, 'opened-message-sentinel');
    assert.equal(harness.tabs.createTab.getAttribute('aria-selected'), 'true');
    assert.equal(harness.tabs.openTab.getAttribute('aria-selected'), 'false');
    assert.equal(harness.panels.createPanel.hidden, false);
    assert.equal(harness.panels.openPanel.hidden, true);
    assert.equal(
        harness.elements.get('session-unified-workspace').classList.contains('is-send-capable'),
        true
    );
    assert.equal(
        harness.elements.get('session-workspace-status-label').textContent,
        'Bonding active'
    );
    assert.deepEqual(harness.navigationCalls, []);
});

test('missing or false session send state leaves the bond-locked UI unchanged', () => {
    for (const payload of [{}, { session_can_send: false }]) {
        const harness = makeHarness();

        harness.applyState(payload);

        assert.equal(harness.elements.get('bond-pending-composer').hidden, false);
        assert.equal(harness.elements.get('message-composer').hidden, true);
        assert.equal(harness.elements.get('y-responder-warning').hidden, false);
        assert.equal(harness.elements.get('bonded-checklist').hidden, true);
        assert.equal(harness.document.body.dataset.dropAttach, 'false');
        assert.equal(
            harness.elements.get('rendered-message').textContent,
            'opened-message-sentinel'
        );
        assert.equal(harness.tabs.createTab.getAttribute('aria-selected'), 'false');
        assert.equal(harness.tabs.openTab.getAttribute('aria-selected'), 'true');
        assert.deepEqual(harness.navigationCalls, []);
    }
});

test('switching actions does not clear or hide the opened result content', () => {
    const harness = makeHarness();
    const openedMessage = harness.elements.get('rendered-message');

    harness.activateAction('create');
    harness.activateAction('open');

    assert.equal(openedMessage.textContent, 'opened-message-sentinel');
    assert.equal(harness.elements.has('rendered-message'), true);
    assert.equal(harness.tabs.createTab.getAttribute('aria-selected'), 'false');
    assert.equal(harness.tabs.openTab.getAttribute('aria-selected'), 'true');
    assert.equal(harness.navigationCalls.length, 0);
});

test('normal and carrier open paths apply state only after rendering decrypted content', () => {
    const orderedCalls = SESSION_JS.match(
        /renderDecryptedMessage\(data\);\s*applyPostOpenSessionState\(data\);/g
    ) || [];
    assert.equal(orderedCalls.length, 2);

    const helper = SESSION_JS.match(
        /function applyPostOpenSessionState\(data\) \{[\s\S]*?\n\}/
    );
    assert.ok(helper);
    assert.doesNotMatch(
        helper[0],
        /renderDecryptedMessage|clearOpenMessageState|location\.|replaceChildren|innerHTML|rendered-message/
    );
});
