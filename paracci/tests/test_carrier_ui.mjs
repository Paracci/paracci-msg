import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const CARRIER_JS = fs.readFileSync(
    path.resolve(TEST_DIR, '../app/static/js/carrier.js'),
    'utf8'
);
const SETUP_JS = fs.readFileSync(
    path.resolve(TEST_DIR, '../app/static/js/setup.js'),
    'utf8'
);
const SESSION_JS = fs.readFileSync(
    path.resolve(TEST_DIR, '../app/static/js/session.js'),
    'utf8'
);
const APP_JS = fs.readFileSync(
    path.resolve(TEST_DIR, '../app/static/js/app.js'),
    'utf8'
);

function makeHarness({ fetchImpl, nativeApi = null } = {}) {
    const anchors = [];
    const objectUrls = [];
    const revokedUrls = [];
    const notices = [];

    const document = {
        body: {
            appendChild(node) {
                node.parentNode = this;
            }
        },
        createElement(tag) {
            if (tag === 'a') {
                const anchor = {
                    clicked: false,
                    removed: false,
                    click() {
                        this.clicked = true;
                    },
                    remove() {
                        this.removed = true;
                    }
                };
                anchors.push(anchor);
                return anchor;
            }
            return { className: '', textContent: '' };
        }
    };
    const TestURL = {
        createObjectURL(blob) {
            const value = `blob:carrier-${objectUrls.length + 1}`;
            objectUrls.push({ value, blob });
            return value;
        },
        revokeObjectURL(value) {
            revokedUrls.push(value);
        }
    };
    const window = {
        PARACCI_I18N: {
            carrier_generic_error: 'Localized generic carrier error.',
            carrier_capacity_error: 'Localized capacity error.',
            carrier_processing: 'Carrier busy.'
        },
        URL: TestURL,
        fetch: fetchImpl || (async () => {
            throw new Error('network sentinel');
        }),
        pywebview: nativeApi ? { api: nativeApi } : undefined,
        ParacciSecurity: {
            getLoopbackToken: () => 'loopback-token',
            navigateAuthorized: async () => true
        },
        showDownloadNotification(filename, savedPath) {
            notices.push({ filename, savedPath });
        }
    };
    const context = vm.createContext({
        Blob,
        document,
        window
    });
    vm.runInContext(CARRIER_JS, context, { filename: 'carrier.js' });

    return {
        anchors,
        api: window.ParacciCarrierUI,
        notices,
        objectUrls,
        revokedUrls,
        window
    };
}

test('generic carrier errors use localized text-safe rendering only', () => {
    const { api } = makeHarness();
    const children = [];
    const container = {
        replaceChildren() {
            children.length = 0;
        },
        appendChild(child) {
            children.push(child);
        }
    };

    api.showGenericError(container);

    assert.equal(children.length, 1);
    assert.equal(children[0].className, 'alert alert-error');
    assert.equal(children[0].textContent, 'Localized generic carrier error.');
});

test('network and backend failures do not expose sentinel details', async () => {
    const network = makeHarness({
        fetchImpl: async () => {
            throw new Error('payload-token-path-sentinel');
        }
    });
    await assert.rejects(
        network.api.submitOpen('/session/id/carrier/open', {}),
        error => {
            assert.equal(error.message, 'Localized generic carrier error.');
            assert.doesNotMatch(error.message, /payload|token|path|sentinel/);
            return true;
        }
    );

    let jsonRead = false;
    const backend = makeHarness({
        fetchImpl: async () => ({
            ok: false,
            async json() {
                jsonRead = true;
                return { error: 'backend-magic-checksum-sentinel' };
            }
        })
    });
    await assert.rejects(
        backend.api.submitOpen('/session/id/carrier/open', {}),
        /Localized generic carrier error/
    );
    assert.equal(jsonRead, false);
});

test('carrier imports follow only authenticated redirect navigation', async () => {
    let navigatedTo = '';
    const harness = makeHarness({
        fetchImpl: async () => ({
            ok: true,
            redirected: true,
            url: 'http://127.0.0.1/session/opaque'
        })
    });
    harness.window.ParacciSecurity.navigateAuthorized = async url => {
        navigatedTo = url;
        return true;
    };

    await harness.api.submitImport('/session/import/carrier', {});

    assert.equal(navigatedTo, 'http://127.0.0.1/session/opaque');
});

test('browser carrier output uses a blob URL download', async () => {
    const blob = new Blob(['png']);
    const harness = makeHarness({
        fetchImpl: async () => ({
            ok: true,
            headers: {
                get(name) {
                    return name === 'Content-Disposition'
                        ? 'attachment; filename="holiday-photo-carrier.png"'
                        : null;
                }
            },
            async blob() {
                return blob;
            }
        })
    });

    await harness.api.submitDownload('/session/id/carrier/export', {});

    assert.equal(harness.anchors.length, 1);
    assert.equal(harness.anchors[0].download, 'holiday-photo-carrier.png');
    assert.equal(harness.anchors[0].clicked, true);
    assert.equal(harness.anchors[0].removed, true);
    assert.equal(harness.objectUrls[0].blob, blob);
    assert.deepEqual(harness.revokedUrls, [harness.objectUrls[0].value]);
});

test('native carrier output consumes the existing one-shot save grant', async () => {
    const calls = [];
    const nativeApi = {
        async save_file_silent(token, loopbackToken) {
            calls.push({ token, loopbackToken });
            return 'managed-output';
        }
    };
    let nativeHeader = '';
    const harness = makeHarness({
        nativeApi,
        fetchImpl: async (_url, init) => {
            nativeHeader = init.headers['X-Paracci-Native-Save'];
            return {
                ok: true,
                async json() {
                    return {
                        native_save_token: 'one-shot-grant',
                        filename: 'holiday-photo-carrier.png'
                    };
                }
            };
        }
    });

    await harness.api.submitDownload('/session/id/carrier/export', {});

    assert.equal(nativeHeader, '1');
    assert.deepEqual(calls, [{
        token: 'one-shot-grant',
        loopbackToken: 'loopback-token'
    }]);
    assert.deepEqual(harness.notices, [{
        filename: 'holiday-photo-carrier.png',
        savedPath: 'managed-output'
    }]);
});

test('capacity failures use localized safe text without reading backend details', async () => {
    let jsonRead = false;
    let textRead = false;
    const harness = makeHarness({
        fetchImpl: async () => ({
            ok: false,
            status: 422,
            async json() {
                jsonRead = true;
                return { error: 'capacity-byte-count-path-sentinel' };
            },
            async text() {
                textRead = true;
                return 'capacity-byte-count-path-sentinel';
            }
        })
    });

    await assert.rejects(
        harness.api.submitDownload('/session/id/carrier/seal', {}),
        error => {
            assert.equal(error.kind, 'capacity');
            assert.equal(error.message, 'Localized capacity error.');
            assert.doesNotMatch(error.message, /byte|count|path|sentinel/);
            return true;
        }
    );
    assert.equal(jsonRead, false);
    assert.equal(textRead, false);
});

test('carrier filenames reject path-like or unsafe response values', () => {
    const { api } = makeHarness();

    assert.equal(
        api.safePngFilename('attachment; filename="holiday-photo-carrier.png"'),
        'holiday-photo-carrier.png'
    );
    assert.equal(api.safePngFilename('../../private.png'), 'image-carrier.png');
    assert.equal(api.safePngFilename('token sentinel.txt'), 'image-carrier.png');
});

test('selected carrier filenames render through textContent', () => {
    const { api } = makeHarness();
    const output = {
        dataset: { emptyLabel: 'No PNG selected' },
        textContent: ''
    };
    const input = {
        files: [{ name: '<img src=x onerror=token-sentinel>.png' }],
        closest() {
            return {
                querySelector() {
                    return output;
                }
            };
        }
    };

    api.updateSelectedFileName(input);

    assert.equal(output.textContent, '<img src=x onerror=token-sentinel>.png');
    assert.equal('innerHTML' in output, false);
});

test('page wiring uses explicit multipart carrier fields only', () => {
    assert.match(SETUP_JS, /formData\.delete\('paracci_file'\)/);
    assert.match(SETUP_JS, /formData\.delete\('native_file_id'\)/);
    assert.match(SETUP_JS, /formData\.set\('carrier_png'/);
    assert.match(SESSION_JS, /formData\.set\('carrier_png'/);
    assert.match(SESSION_JS, /formData\.set\('cover_png'/);
    assert.match(SESSION_JS, /new FormData\(sourceForm\)/);
    for (const requiredField of [
        'message',
        'ttl_seconds',
        'allow_download',
        'attachments',
        'staged_attachment_ids'
    ]) {
        assert.doesNotMatch(SESSION_JS, new RegExp(`formData\\.delete\\('${requiredField}'\\)`));
    }
    assert.match(CARRIER_JS, /png_lossless_v1/);

    const combined = CARRIER_JS + SETUP_JS + SESSION_JS;
    for (const forbidden of [
        'carrier_native_file_id',
        'cover_native_file_id',
        'FileReader',
        'readAsDataURL',
        'readAsArrayBuffer',
        'btoa(',
        'atob(',
        'qr_matrix_v1'
    ]) {
        assert.doesNotMatch(combined, new RegExp(forbidden.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    }
    assert.doesNotMatch(combined, /\.save_file\(/);
});

test('normal drop intent remains limited to paracci files and attachments', () => {
    const match = APP_JS.match(
        /function resolveDropIntent\(fileInfo = \{\}\) \{([\s\S]*?)\n\}/
    );
    assert.ok(match);
    assert.match(match[1], /\.paracci/);
    assert.doesNotMatch(match[1], /\.png|carrier/i);
});
