// Paracci Secure Messaging - Global Application Logic
// Security Hardening & UI Notifications

(function initParacciI18n() {
    const source = document.getElementById('paracci-i18n-json');
    if (!source) {
        window.PARACCI_I18N = window.PARACCI_I18N || {};
        return;
    }
    try {
        window.PARACCI_I18N = JSON.parse(source.content?.textContent || source.textContent || '{}');
    } catch (err) {
        console.error('[Paracci] Failed to parse i18n payload:', err);
        window.PARACCI_I18N = window.PARACCI_I18N || {};
    }
})();

(function applyInitialSidebarState() {
    if (localStorage.getItem('paracci_sidebar_collapsed') === 'true') {
        document.body?.classList.add('sidebar-collapsed');
    }
})();

(function initLoopbackRequestSecurity() {
    if (window.__paracciLoopbackSecurityInstalled) return;
    window.__paracciLoopbackSecurityInstalled = true;

    function readMeta(name) {
        return document.querySelector(`meta[name="${name}"]`)?.getAttribute('content') || '';
    }

    function getLoopbackToken() {
        return window.pywebview?.token || window.__PARACCI_NATIVE_TOKEN || readMeta('paracci-browser-token');
    }

    function getCsrfToken() {
        return readMeta('paracci-csrf-token');
    }

    function isSameOriginRequest(input) {
        try {
            const rawUrl = input instanceof Request ? input.url : input;
            return new URL(rawUrl || window.location.href, window.location.href).origin === window.location.origin;
        } catch (err) {
            return false;
        }
    }

    function upsertHidden(form, name, value) {
        let input = form.querySelector(`input[name="${name}"]`);
        if (!input) {
            input = document.createElement('input');
            input.type = 'hidden';
            input.name = name;
            form.appendChild(input);
        }
        input.value = value;
    }

    const nativeFetch = window.fetch.bind(window);
    window.fetch = function paracciFetch(input, init = {}) {
        if (!isSameOriginRequest(input)) {
            return nativeFetch(input, init);
        }

        const token = getLoopbackToken();
        const csrf = getCsrfToken();
        const nextInit = { ...init };
        const headers = new Headers(input instanceof Request ? input.headers : undefined);
        if (init?.headers) {
            new Headers(init.headers).forEach((value, key) => headers.set(key, value));
        }
        if (token) headers.set('X-Paracci-Token', token);
        if (csrf) headers.set('X-CSRF-Token', csrf);
        nextInit.headers = headers;
        if (!Object.prototype.hasOwnProperty.call(nextInit, 'credentials')) {
            nextInit.credentials = 'same-origin';
        }
        return nativeFetch(input, nextInit);
    };

    document.addEventListener('submit', e => {
        const form = e.target;
        if (!(form instanceof HTMLFormElement) || !isSameOriginRequest(form.action)) return;

        const token = getLoopbackToken();
        const csrf = getCsrfToken();
        if (!token || !csrf) {
            e.preventDefault();
            showNotification(window.PARACCI_I18N?.server_error || 'Security token is not available.', 'error');
            return;
        }

        upsertHidden(form, '_paracci_token', token);
        upsertHidden(form, '_csrf_token', csrf);
    }, true);

    window.ParacciSecurity = {
        getLoopbackToken,
        getCsrfToken,
        isSameOriginRequest
    };
})();

document.addEventListener('DOMContentLoaded', () => {
    // 1. Context Menu & DevTools Prevention
    document.addEventListener('contextmenu', e => e.preventDefault());

    document.addEventListener('keydown', e => {
        // DevTools & Inspector
        if (e.key === 'F12') e.preventDefault();
        if (e.ctrlKey && e.shiftKey && ['I','J','C','K'].includes(e.key)) e.preventDefault();
        
        // View Source & Page Actions
        if (e.ctrlKey && ['u','s','p','h','j'].includes(e.key.toLowerCase())) e.preventDefault();
        
        // Refresh (To maintain state)
        if (e.key === 'F5' || (e.ctrlKey && e.key.toLowerCase() === 'r')) e.preventDefault();
        
        // Zoom Controls (To prevent UI breakage)
        if (e.ctrlKey && (e.key === '+' || e.key === '-' || e.key === '0')) e.preventDefault();
    });

    // 2. Desktop shell state and route-aware drag-drop
    initSidebarCollapse();
    bindGlobalShellControls();
    setupGlobalDropExperience();
    initUpdateBanner();

    // 3. Focus settings TOTP verification code input if present
    const settingsCode = document.getElementById('authCodeInput');
    if (settingsCode) settingsCode.focus();

    document.addEventListener('dragstart', e => e.preventDefault());
});


/**
 * Initializes the persisted desktop sidebar collapse state.
 */
function initSidebarCollapse() {
    const collapsed = localStorage.getItem('paracci_sidebar_collapsed') === 'true';
    setSidebarCollapsed(collapsed);
}

function setSidebarCollapsed(collapsed) {
    // Only toggle class and save to localStorage if state actually changed
    // or if we are forced to (init)
    const hasClass = document.body.classList.contains('sidebar-collapsed');
    if (hasClass !== collapsed) {
        document.body.classList.toggle('sidebar-collapsed', collapsed);
    }
    localStorage.setItem('paracci_sidebar_collapsed', collapsed ? 'true' : 'false');

    // Always update the toggle button UI regardless of class presence
    const toggle = document.querySelector('.sidebar-toggle');
    if (toggle) {
        const label = collapsed
            ? (document.body.dataset.sidebarExpand || window.PARACCI_I18N?.sidebar_expand || 'Expand sidebar')
            : (document.body.dataset.sidebarCollapse || window.PARACCI_I18N?.sidebar_collapse || 'Collapse sidebar');
        toggle.setAttribute('aria-label', label);
        toggle.setAttribute('title', label);
    }
}

function toggleSidebarCollapsed() {
    setSidebarCollapsed(!document.body.classList.contains('sidebar-collapsed'));
}

function bindGlobalShellControls() {
    document.querySelector('.sidebar-toggle')?.addEventListener('click', toggleSidebarCollapsed);
    document.getElementById('download-toast')?.addEventListener('click', handleToastClick);
}

function getDropContext() {
    const ds = document.body?.dataset || {};
    return {
        endpoint: ds.endpoint || '',
        sessionId: ds.currentSessionId || '',
        role: ds.sessionRole || '',
        state: ds.sessionState || '',
        canImport: ds.dropImport === 'true',
        canFinalize: ds.dropFinalize === 'true',
        canOpen: ds.dropOpen === 'true',
        canAttach: ds.dropAttach === 'true',
        labels: {
            import: ds.dropLabelImport || window.PARACCI_I18N?.drop_import_session || 'Import session',
            finalize: ds.dropLabelFinalize || window.PARACCI_I18N?.drop_finalize_bond || 'Finalize bond',
            open: ds.dropLabelOpen || window.PARACCI_I18N?.drop_open_message || 'Open message',
            attach: ds.dropLabelAttach || window.PARACCI_I18N?.drop_attach_files || 'Attach files',
            unsupported: ds.dropLabelUnsupported || window.PARACCI_I18N?.drop_unsupported || 'Unsupported drop',
            unsupportedDesc: ds.dropDescUnsupported || window.PARACCI_I18N?.drop_unsupported_desc || 'This file cannot be dropped here.'
        }
    };
}

function resolveDropIntent(fileInfo = {}) {
    const ctx = getDropContext();
    const name = (fileInfo.name || fileInfo.path || '').toLowerCase();
    const isParacci = fileInfo.isParacci ?? name.endsWith('.paracci');

    if (isParacci && ctx.canImport) return { type: 'import', context: ctx };
    if (isParacci && ctx.canFinalize) return { type: 'finalize', context: ctx };
    if (isParacci && ctx.canOpen) return { type: 'open', context: ctx };
    if (!isParacci && ctx.canAttach) return { type: 'attach', context: ctx };
    return { type: 'unsupported', context: ctx };
}

function getDropTargetForIntent(intentType) {
    const ids = {
        import: 'file-drop-area',
        finalize: 'responder-drop-area',
        open: 'session-drop-zone',
        attach: 'attachment-drop-zone'
    };
    return document.getElementById(ids[intentType]);
}

function clearDropTargetState() {
    document.querySelectorAll('.drop-target-active').forEach(el => el.classList.remove('drop-target-active'));
}

function showDropHint(intentType) {
    const ctx = getDropContext();
    const overlay = document.getElementById('global-drop-overlay');
    const title = document.getElementById('drop-hint-title');
    const desc = document.getElementById('drop-hint-desc');
    const label = ctx.labels[intentType] || ctx.labels.unsupported;

    clearDropTargetState();
    
    // Primary highlight
    getDropTargetForIntent(intentType)?.classList.add('drop-target-active');

    // Ambiguous drag phase: highlight both if in session
    if (intentType === 'attach' && ctx.canOpen) {
        getDropTargetForIntent('open')?.classList.add('drop-target-active');
    }

    if (title) title.textContent = label;
    if (desc) desc.textContent = intentType === 'unsupported' ? ctx.labels.unsupportedDesc : '';
    overlay?.classList.add('active');
}

function hideDropHint() {
    clearDropTargetState();
    document.getElementById('global-drop-overlay')?.classList.remove('active');
}

function setupGlobalDropExperience() {
    let dragCounter = 0;

    window.addEventListener('dragenter', e => {
        e.preventDefault();
        dragCounter++;
        const fallback = resolveDropIntent({});
        showDropHint(fallback.type);
    });

    window.addEventListener('dragleave', e => {
        e.preventDefault();
        dragCounter--;
        if (dragCounter <= 0) {
            dragCounter = 0;
            hideDropHint();
        }
    });

    window.addEventListener('dragover', e => {
        e.preventDefault();
    });

    window.addEventListener('drop', e => {
        e.preventDefault();
        dragCounter = 0;
        hideDropHint();

        const files = e.dataTransfer.files;
        if (files && files.length > 0) {
            handleGlobalDrop(files);
        }
    });
    window.addEventListener('dragend', e => {
        e.preventDefault();
        dragCounter = 0;
        hideDropHint();
    });
}

function setFiles(input, files, dispatchChange = true) {
    if (!input || !files?.length) return;
    const dt = new DataTransfer();
    for (const file of files) dt.items.add(file);
    input.files = dt.files;
    if (dispatchChange) input.dispatchEvent(new Event('change', { bubbles: true }));
}

function setNativeFileRef(form, fileRef) {
    let input = form?.querySelector('input[name="native_file_id"]');
    if (!form) return null;
    if (!input) {
        input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'native_file_id';
        form.appendChild(input);
    }
    input.value = fileRef?.id || '';
    form.querySelector('input[type="file"]')?.removeAttribute('required');
    return input;
}

function requestFormSubmit(form) {
    if (!form) return;
    if (typeof form.requestSubmit === 'function') {
        form.requestSubmit();
    } else {
        const event = new Event('submit', { bubbles: true, cancelable: true });
        if (form.dispatchEvent(event)) {
            HTMLFormElement.prototype.submit.call(form);
        }
    }
}

function rememberStagedAttachment(item) {
    window.PARACCI_STAGED_ATTACHMENTS = window.PARACCI_STAGED_ATTACHMENTS || [];
    window.PARACCI_STAGED_ATTACHMENTS.push(item);
    const hidden = document.getElementById('staged_attachment_ids');
    if (hidden) {
        hidden.value = window.PARACCI_STAGED_ATTACHMENTS.map(att => att.id).join(',');
    }
    if (typeof window.updateAttachmentBadge === 'function') window.updateAttachmentBadge();
}

function rememberStagedAttachments(items) {
    const attachments = Array.isArray(items) ? items : [];
    attachments.forEach(rememberStagedAttachment);
    if (!attachments.length) return;
    const label = attachments.length === 1
        ? (window.PARACCI_I18N?.attachment_attached || "{filename} attached.").replace("{filename}", attachments[0].filename)
        : (window.PARACCI_I18N?.attachments_added || "{count} file(s) added.").replace("{count}", attachments.length);
    showNotification(label);
}

function clearStagedAttachments({ keepalive = false } = {}) {
    const stagedIds = (window.PARACCI_STAGED_ATTACHMENTS || [])
        .map(att => att?.id)
        .filter(Boolean);
    if (stagedIds.length) {
        fetch(window.PARACCI_CONFIG?.cache_clear_url || '/api/sensitive-cache/clear', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ preview_ids: [], staged_attachment_ids: stagedIds }),
            keepalive
        }).catch(err => console.warn('[Paracci] Staged attachment cache clear failed:', err));
    }
    window.PARACCI_STAGED_ATTACHMENTS = [];
    const hidden = document.getElementById('staged_attachment_ids');
    if (hidden) hidden.value = '';
    if (typeof window.updateAttachmentBadge === 'function') window.updateAttachmentBadge();
}

function addNativeStagedAttachments(data) {
    if (!data?.success) {
        throw new Error(data.error || window.PARACCI_I18N?.msg_not_processed || 'Attachment could not be staged.');
    }
    rememberStagedAttachments(data.attachments || []);
}

async function stageNativeAttachmentsFromPicker() {
    const api = window.pywebview?.api;
    if (!api?.select_attachments) return false;
    const data = await api.select_attachments();
    addNativeStagedAttachments(data);
    return true;
}

function receiveNativeStagedAttachments(data) {
    try {
        addNativeStagedAttachments(data);
    } catch (err) {
        console.error('[Paracci] Native attachment staging failed:', err);
        showNotification(err.message || window.PARACCI_I18N?.drop_failed || 'Drop failed.', 'error');
    }
}

function updateOpenFileLabel(name) {
    const label = document.getElementById('file-label');
    if (label && name) label.textContent = name;
}

async function executeDropIntent(intent, payload) {
    switch (intent.type) {
        case 'import': {
            const form = document.getElementById('importForm');
            if (payload.isNative) {
                setNativeFileRef(form, payload.fileRef);
                if (typeof window.updateNativeUI === 'function') window.updateNativeUI(payload.fileRef);
            } else {
                setFiles(document.getElementById('fileInput'), payload.files);
            }
            showDropHint('import');
            setTimeout(hideDropHint, 800);
            break;
        }
        case 'finalize': {
            const form = document.getElementById('responder-form');
            if (payload.isNative) {
                setNativeFileRef(form, payload.fileRef);
            } else {
                setFiles(document.getElementById('responder-input'), payload.files, false);
            }
            requestFormSubmit(form);
            break;
        }
        case 'open': {
            const form = document.getElementById('open-message-form');
            if (payload.isNative) {
                setNativeFileRef(form, payload.fileRef);
                updateOpenFileLabel(payload.name);
            } else {
                setFiles(document.getElementById('paracci_file'), payload.files);
                updateOpenFileLabel(payload.files?.[0]?.name);
            }
            break;
        }
        case 'attach': {
            if (payload.isNative) {
                receiveNativeStagedAttachments({ success: true, attachments: payload.attachments || [] });
            } else {
                setFiles(document.getElementById('attachments'), payload.files);
                if (typeof window.updateAttachmentBadge === 'function') window.updateAttachmentBadge();
                const notifyMsg = (window.PARACCI_I18N?.attachments_added || "{count} file(s) added.").replace("{count}", payload.files.length);
                showNotification(notifyMsg);
            }
            break;
        }
        default:
            showNotification(intent.context.labels.unsupportedDesc);
            showDropHint('unsupported');
            setTimeout(hideDropHint, 1000);
    }
}

function handleGlobalDrop(files) {
    const file = files[0];
    const intent = resolveDropIntent({ name: file?.name || '', isNative: false });
    executeDropIntent(intent, { files, isNative: false }).catch(err => {
        console.error('[Paracci] Drop handling failed:', err);
        showNotification(err.message || window.PARACCI_I18N?.drop_failed || 'Drop failed.', 'error');
    });
}

function handleNativeFileRef(fileRef) {
    const name = fileRef?.filename || '';
    const intent = resolveDropIntent({ name, isNative: true });
    executeDropIntent(intent, { fileRef, name, isNative: true }).catch(err => {
        console.error('[Paracci] Native drop handling failed:', err);
        showNotification(err.message || window.PARACCI_I18N?.drop_failed || 'Drop failed.', 'error');
    });
}

window.toggleSidebarCollapsed = toggleSidebarCollapsed;
window.resolveDropIntent = resolveDropIntent;
window.handleNativeFileRef = handleNativeFileRef;
window.rememberStagedAttachment = rememberStagedAttachment;
window.rememberStagedAttachments = rememberStagedAttachments;
window.receiveNativeStagedAttachments = receiveNativeStagedAttachments;
window.stageNativeAttachmentsFromPicker = stageNativeAttachmentsFromPicker;
window.clearStagedAttachments = clearStagedAttachments;

window.addEventListener('pagehide', () => clearStagedAttachments({ keepalive: true }));
window.addEventListener('beforeunload', () => clearStagedAttachments({ keepalive: true }));

// 3. Download Notifications (Global functions)
let _currentDownloadPath = null;

function showDownloadNotification(filename, path) {
    _currentDownloadPath = path;
    const toast = document.getElementById('download-toast');
    const label = document.getElementById('toast-filename');
    if (!toast || !label) return;
    label.textContent = filename;
    toast.classList.add('active');
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => toast.classList.remove('active'), 8000);
}

function handleToastClick() {
    if (_currentDownloadPath && window.pywebview?.api) {
        window.pywebview.api.open_file_location(_currentDownloadPath);
        document.getElementById('download-toast')?.classList.remove('active');
    }
}

// 4. Process-local application update notification and progress banner
let _updateStatus = null;
let _updatePollTimer = null;
let _updateAckVersion = '';

function updateString(key, fallback, values = {}) {
    let result = window.PARACCI_I18N?.[key] || fallback;
    Object.entries(values).forEach(([name, value]) => {
        result = result.replace(`{${name}}`, value);
    });
    return result;
}

function formatUpdateSize(rawSize) {
    const bytes = Number(rawSize);
    if (!Number.isFinite(bytes) || bytes <= 0) return '';
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
}

function scheduleUpdatePoll(delay = 1000) {
    clearTimeout(_updatePollTimer);
    _updatePollTimer = setTimeout(fetchUpdateStatus, delay);
}

async function fetchUpdateStatus() {
    try {
        const response = await fetch('/api/update/status', { cache: 'no-store' });
        if (!response.ok) return;
        const status = await response.json();
        renderUpdateBanner(status);
        if (['checking', 'downloading', 'verifying'].includes(status.state)) {
            scheduleUpdatePoll();
        }
    } catch (_err) {
        // Startup checks intentionally remain silent when the local shell is closing.
    }
}

async function postUpdateAction(path, payload = {}) {
    try {
        const response = await fetch(path, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const status = await response.json();
        if (!response.ok) {
            if (status.error_code === 'protocol_ack_required') return;
            showNotification(updateString('update_error_download_failed', 'Could not start the update.'), 'error');
            return;
        }
        renderUpdateBanner(status);
        if (['downloading', 'verifying'].includes(status.state)) scheduleUpdatePoll(250);
    } catch (_err) {
        showNotification(updateString('update_error_download_failed', 'Could not start the update.'), 'error');
    }
}

function updateStatusMessage(status) {
    const errors = {
        download_failed: ['update_error_download_failed', 'Could not download the update. Try again later.'],
        checksum_missing: ['update_error_checksum_missing', 'The release checksum entry is missing. Installation was stopped.'],
        checksum_failed: ['update_error_checksum_failed', 'Checksum verification failed. The downloaded installer was deleted.'],
        size_mismatch: ['update_error_size_mismatch', 'The downloaded file size did not match the release asset. Installation was stopped.'],
        browser_open_failed: ['update_error_browser_open_failed', 'Could not open the releases page.'],
        installer_missing: ['update_error_installer_missing', 'The verified installer is no longer available.']
    };
    if (status.error_code && errors[status.error_code]) {
        return updateString(...errors[status.error_code]);
    }
    if (status.state === 'downloading') return updateString('update_downloading', 'Downloading update...');
    if (status.state === 'verifying') return updateString('update_verifying', 'Verifying SHA-256 checksum...');
    if (status.state === 'ready') {
        return `${updateString('update_verified', 'Checksum verified.')} ${updateString('update_ready', 'Ready to install. The application will close.')}`;
    }
    if (status.state === 'cancelled') return updateString('update_cancelled', 'Download cancelled.');
    return '';
}

function renderUpdateBanner(status) {
    _updateStatus = status;
    const banner = document.getElementById('update-banner');
    if (!banner) return;
    if (!status?.visible) {
        banner.hidden = true;
        clearTimeout(_updatePollTimer);
        return;
    }
    banner.hidden = false;
    const versionLine = document.getElementById('update-version-line');
    const notes = document.getElementById('update-release-notes');
    const warning = document.getElementById('update-protocol-warning');
    const warningText = document.getElementById('update-protocol-warning-text');
    const ack = document.getElementById('update-protocol-ack');
    const primary = document.getElementById('update-primary-btn');
    const cancel = document.getElementById('update-cancel-btn');
    const progressPanel = document.getElementById('update-progress-panel');
    const progressFill = document.getElementById('update-progress-fill');
    const progressPercent = document.getElementById('update-progress-percent');
    const size = document.getElementById('update-download-size');
    const statusText = document.getElementById('update-status-text');

    versionLine.textContent = updateString(
        'update_version_line',
        'Current {current} - New {latest}',
        { current: status.current_version, latest: status.latest_version }
    );
    notes.textContent = status.release_notes || '';
    notes.hidden = !status.release_notes;

    if (_updateAckVersion !== status.latest_version) {
        ack.checked = false;
        _updateAckVersion = status.latest_version;
    }
    warning.hidden = !status.protocol_warning;
    warningText.textContent = status.protocol_unknown
        ? updateString('update_protocol_unknown', 'This release does not provide session protocol compatibility information. After updating, you may need to establish new sessions with your contacts.')
        : updateString('update_protocol_warning', 'This update changes the session protocol. After updating, you will need to establish new sessions with your contacts.');

    const busy = ['downloading', 'verifying', 'installing'].includes(status.state);
    const hasProgress = ['downloading', 'verifying', 'ready'].includes(status.state);
    progressPanel.hidden = !hasProgress;
    progressFill.style.width = `${Number(status.progress_percent || 0)}%`;
    progressPercent.textContent = `${Number(status.progress_percent || 0)}%`;
    const formattedSize = formatUpdateSize(status.size_bytes);
    size.textContent = formattedSize
        ? updateString('update_size', 'Size: {size}', { size: formattedSize })
        : '';

    const message = updateStatusMessage(status);
    statusText.textContent = message;
    statusText.hidden = !message;
    statusText.classList.toggle('error', Boolean(status.error_code));

    primary.hidden = busy;
    cancel.hidden = !['downloading', 'verifying'].includes(status.state);
    if (status.state === 'ready') {
        primary.textContent = updateString('update_install_now', 'Install Update');
    } else if (status.action === 'browser') {
        primary.textContent = updateString('update_open_releases', 'View Download');
    } else {
        primary.textContent = updateString('update_update_now', 'Update Now');
    }
    primary.disabled = status.protocol_warning && !ack.checked;
}

function initUpdateBanner() {
    const banner = document.getElementById('update-banner');
    if (!banner) return;
    document.getElementById('update-protocol-ack')?.addEventListener('change', () => {
        if (_updateStatus) renderUpdateBanner(_updateStatus);
    });
    document.getElementById('update-dismiss-btn')?.addEventListener('click', () => {
        postUpdateAction('/api/update/dismiss');
    });
    document.getElementById('update-cancel-btn')?.addEventListener('click', () => {
        postUpdateAction('/api/update/cancel');
    });
    document.getElementById('update-primary-btn')?.addEventListener('click', async () => {
        if (_updateStatus?.state === 'ready') {
            if (window.pywebview?.api?.install_verified_update) {
                await window.pywebview.api.install_verified_update();
            } else {
                showNotification(updateString('update_error_installer_missing', 'Installer launch is unavailable.'), 'error');
            }
            return;
        }
        await postUpdateAction('/api/update/download', {
            acknowledge_protocol_warning: Boolean(document.getElementById('update-protocol-ack')?.checked)
        });
    });
    fetchUpdateStatus();
}

// 5. Argon2id Work Overlay Helpers
let _argonAnimationId = null;
let _argonState = 'idle'; // 'idle', 'loading', 'finishing', 'fade-wait', 'fading'
let _argonStartTime = 0;
let _argonFinishStartTime = 0;
let _argonFadeStartTime = 0;
let _argonStartPercent = 0;
let _argonCurrentPercent = 0;
const MIN_ARGON_OVERLAY_DISPLAY_MS = 800; // minimum display duration to prevent flickering
let _argonEstDuration = 800;
let _argonBackendFinished = false;
let _argonWorkBenchmarkData = null;

const loaderI18n = {
    tr: {
        init: "Kanal Başlatılıyor...",
        accept: "Davet Kabul Ediliyor...",
        finalize: "Bağlantı Tamamlanıyor...",
        seal: "Mesaj Kilitleniyor...",
        open: "Kilit Açılıyor...",
        default: "İşlem Yapılıyor...",
        p_standard: "Standart Profil - Güvenli ve Hızlı Şifreleme (~0.1s)",
        p_paranoid: "Paranoid Profil - Yüksek Güvenlik (~0.8s)",
        p_quantum: "Quantum Profil - Post-Quantum Koruması (~3-4dk) - Lütfen bekleyin, bu işlem bilgisayarınızın donanımına bağlıdır.",
        p_custom: "Özel Profil - Argon2id Korumalı Şifreleme",
        desc_init: "Kanal anahtarları oluşturuluyor ve el sıkışma başlatılıyor.",
        desc_accept: "Argon2id zaman-kilitli anahtar türetimi gerçekleştiriliyor. Donma hissi oluşabilir, bu normaldir.",
        desc_finalize: "Karşı tarafın anahtar doğrulaması yapılıyor ve oturum tamamlanıyor.",
        desc_seal: "Mesaj içeriği Argon2id ve ML-KEM hibrit kriptografi ile kilitleniyor.",
        desc_open: "Zarf içeriği çözülüyor, Argon2id koruması aşılıyor."
    },
    en: {
        init: "Initializing Channel...",
        accept: "Accepting Invitation...",
        finalize: "Finalizing Connection...",
        seal: "Sealing Message...",
        open: "Opening Message...",
        default: "Processing...",
        p_standard: "Standard Profile - Secure & Fast Encryption (~0.1s)",
        p_paranoid: "Paranoid Profile - High Security (~0.8s)",
        p_quantum: "Quantum Profile - Post-Quantum Protection (~3-4m) - Please wait, this depends on your hardware.",
        p_custom: "Custom Profile - Argon2id Shielded Encryption",
        desc_init: "Generating channel keys and starting the handshake.",
        desc_accept: "Performing Argon2id time-locked key derivation. Browser response may lag, this is normal.",
        desc_finalize: "Verifying peer's keys and finalizing the secure session.",
        desc_seal: "Sealing message content with Argon2id and ML-KEM hybrid cryptography.",
        desc_open: "Decrypting envelope content and breaking Argon2id time-lock."
    },
    de: {
        init: "Kanal wird initialisiert...",
        accept: "Einladung wird akzeptiert...",
        finalize: "Verbindung wird abgeschlossen...",
        seal: "Nachricht wird versiegelt...",
        open: "Nachricht wird geöffnet...",
        default: "Verarbeitung...",
        p_standard: "Standard-Profil - Sichere und schnelle Verschlüsselung (~0.1s)",
        p_paranoid: "Paranoid-Profil - Hohe Sicherheit (~0.8s)",
        p_quantum: "Quantum-Profil - Post-Quantum-Schutz (~3-4 Min.) - Bitte warten, dies hängt von Ihrer Hardware ab.",
        p_custom: "Benutzerdefiniertes Profil - Argon2id-geschützte Verschlüsselung",
        desc_init: "Kanalschlüssel werden generiert und der Handshake gestartet.",
        desc_accept: "Argon2id-zeitgesperrte Schlüsselableitung wird durchgeführt. Browser kann verzögern, das ist normal.",
        desc_finalize: "Schlüssel des Partners werden überprüft und die sichere Sitzung abgeschlossen.",
        desc_seal: "Nachrichteninhalt wird mit Argon2id und ML-KEM Hybrid-Kryptographie versiegelt.",
        desc_open: "Umschlaginhalt wird entschlüsselt und Argon2id-Zeitsperre aufgehoben."
    },
    es: {
        init: "Inicializando canal...",
        accept: "Aceptando invitación...",
        finalize: "Finalizando conexión...",
        seal: "Sellando mensaje...",
        open: "Abriendo mensaje...",
        default: "Procesando...",
        p_standard: "Perfil estándar - Cifrado rápido y seguro (~0.1s)",
        p_paranoid: "Perfil paranoico - Alta seguridad (~0.8s)",
        p_quantum: "Perfil cuántico - Protección post-cuántica (~3-4 min) - Por favor espere, esto depende de su hardware.",
        p_custom: "Perfil personalizado - Cifrado protegido por Argon2id",
        desc_init: "Generando claves de canal e iniciando el saludo.",
        desc_accept: "Realizando derivación de claves con bloqueo de tiempo Argon2id. El navegador puede ralentizarse, es normal.",
        desc_finalize: "Verificando las claves del par y finalizando la sesión segura.",
        desc_seal: "Sellando el contenido del mensaje con criptografía híbrida Argon2id y ML-KEM.",
        desc_open: "Descifrando el contenido del sobre y rompiendo el bloqueo de tiempo Argon2id."
    },
    fr: {
        init: "Initialisation du canal...",
        accept: "Acceptation de l'invitation...",
        finalize: "Finalisation de la connexion...",
        seal: "Scellement du message...",
        open: "Ouverture du message...",
        default: "Traitement...",
        p_standard: "Profil standard - Chiffrement rapide et sécurisé (~0.1s)",
        p_paranoid: "Profil paranoïaque - Haute sécurité (~0.8s)",
        p_quantum: "Profil quantique - Protection post-quantique (~3-4 min) - Veuillez patienter, cela dépend de votre matériel.",
        p_custom: "Profil personnalisé - Chiffrement protégé par Argon2id",
        desc_init: "Génération des clés de canal et démarrage de la liaison.",
        desc_accept: "Dérivation de clés Argon2id verrouillée dans le temps. Le navigateur peut ralentir, c'est normal.",
        desc_finalize: "Vérification des clés du pair et finalisation de la session sécurisée.",
        desc_seal: "Scellement du contenu du message avec la cryptographie hybride Argon2id et ML-KEM.",
        desc_open: "Déchiffrement du contenu de l'enveloppe et levée du verrouillage temporel Argon2id."
    },
    ru: {
        init: "Инициализация канала...",
        accept: "Принятие приглашения...",
        finalize: "Завершение соединения...",
        seal: "Запечатывание сообщения...",
        open: "Открытие сообщения...",
        default: "Обработка...",
        p_standard: "Стандартный профиль - Быстрое и безопасное шифрование (~0.1s)",
        p_paranoid: "Параноидальный профиль - Высокая безопасность (~0.8s)",
        p_quantum: "Квантовый профиль - Постквантовая защита (~3-4 мин) - Пожалуйста, подождите, это зависит от вашего оборудования.",
        p_custom: "Пользовательский профиль - Шифрование с защитой Argon2id",
        desc_init: "Генерация ключей канала и запуск рукопожатия.",
        desc_accept: "Выполнение криптографического вывода ключей Argon2id. Браузер может зависнуть, это нормально.",
        desc_finalize: "Проверка ключей собеседника и завершение безопасного сеанса.",
        desc_seal: "Запечатывание содержимого сообщения с помощью гибридного шифрования Argon2id и ML-KEM.",
        desc_open: "Расшифровка конверта и обход временной блокировки Argon2id."
    }
};

async function loadBenchmarkData() {
    try {
        const res = await fetch('/api/benchmark-results');
        const json = await res.json();
        if (json.success && json.data && json.data.results) {
            _argonWorkBenchmarkData = json.data.results;
        }
    } catch (err) {
        console.error("Failed to load benchmark data", err);
    }
}

// Initial fetch
loadBenchmarkData();

function getProfileName(t, m, p) {
    t = parseInt(t);
    m = parseInt(m);
    p = parseInt(p);
    if (t === 2 && m === 65536 && p === 2) return "standard";
    if (t === 8 && m === 262144 && p === 4) return "paranoid";
    if (t === 256 && m === 2097152 && p === 2) return "quantum";
    return "custom";
}

function showArgonWorkOverlay(action = 'seal', params = null) {
    const shield = document.getElementById('argonWorkOverlay');
    if (!shield) return;

    if (_argonAnimationId) {
        cancelAnimationFrame(_argonAnimationId);
        _argonAnimationId = null;
    }

    _argonState = 'loading';
    _argonStartTime = performance.now();
    _argonBackendFinished = false;
    _argonCurrentPercent = 0;

    const bar = document.getElementById('argonWorkProgress');
    const pctText = document.getElementById('argonWorkPercent');
    const titleEl = document.getElementById('argonWorkText');
    const descEl = document.getElementById('argonWorkSubtext');

    if (bar) {
        bar.style.transition = 'none'; // Disable CSS transitions for width to avoid lag with RAF updates
        bar.style.width = '0%';
    }
    if (pctText) pctText.textContent = '0%';

    // Detect language
    const lang = document.documentElement.lang || 'tr';
    const dict = loaderI18n[lang] || loaderI18n['tr'];

    // Identify profile
    let profileName = 'standard';
    let customParams = null;
    
    if (typeof params === 'string') {
        profileName = params.toLowerCase();
    } else if (params && typeof params === 'object') {
        if (params.t !== undefined && params.m !== undefined && params.p !== undefined) {
            profileName = getProfileName(params.t, params.m, params.p);
            if (profileName === 'custom') {
                customParams = { t: params.t, m: params.m / 1024, p: params.p }; // Convert back to MB for display
            }
        } else {
            profileName = 'standard';
        }
    } else {
        // Fallback to reading config elements
        const cfg = document.getElementById('paracci-config');
        if (cfg) {
            const t = parseInt(cfg.dataset.securityT || '0');
            const m = parseInt(cfg.dataset.securityM || '0');
            const p = parseInt(cfg.dataset.securityP || '0');
            if (t && m && p) {
                profileName = getProfileName(t, m, p);
                if (profileName === 'custom') {
                    customParams = { t, m: m / 1024, p };
                }
            }
        }
    }

    // Estimate duration
    let estDurationSec = 0.8;
    let isCustom = (profileName === 'custom');

    if (isCustom && customParams) {
        const t = parseInt(customParams.t || 1);
        const m = parseInt(customParams.m || 64);
        const p = parseInt(customParams.p || 1);
        estDurationSec = (t * m) / 640 / Math.max(1, Math.sqrt(p));
    } else {
        const fallbacks = {
            standard: { init_x: 0.040, accept_y: 0.046, finalize_x: 0.049, seal: 0.044, open: 0.045 },
            paranoid: { init_x: 0.001, accept_y: 0.381, finalize_x: 0.400, seal: 0.384, open: 0.378 },
            quantum: { init_x: 0.001, accept_y: 202.9, finalize_x: 223.2, seal: 219.2, open: 211.7 }
        };

        const lookupKey = action === 'init' ? 'init_x' : 
                          action === 'accept' ? 'accept_y' : 
                          action === 'finalize' ? 'finalize_x' : 
                          action === 'seal' ? 'seal' : 
                          action === 'open' ? 'open' : 'seal';

        const db = _argonWorkBenchmarkData || fallbacks;
        const profData = db[profileName] || fallbacks[profileName] || fallbacks['standard'];
        estDurationSec = profData[lookupKey] || 0.8;
    }

    _argonEstDuration = Math.max(MIN_ARGON_OVERLAY_DISPLAY_MS, estDurationSec * 1000);

    // Dynamic text
    if (titleEl) {
        titleEl.textContent = dict[action] || dict.default;
    }
    if (descEl) {
        let profLabel = dict[`p_${profileName}`] || dict.p_standard;
        let actLabel = dict[`desc_${action}`] || '';
        if (isCustom && customParams) {
            profLabel = `${dict.p_custom} (t=${customParams.t}, m=${customParams.m}MB, p=${customParams.p})`;
        }
        descEl.innerHTML = `<strong>${profLabel}</strong><br>${actLabel}`;
    }

    // Show
    shield.classList.add('active');
    shield.style.opacity = '1';

    _argonAnimationId = requestAnimationFrame(updateArgonOverlay);
}

function updateArgonOverlay(timestamp) {
    if (_argonState === 'idle') {
        _argonAnimationId = null;
        return;
    }

    const bar = document.getElementById('argonWorkProgress');
    const pctText = document.getElementById('argonWorkPercent');
    const shield = document.getElementById('argonWorkOverlay');

    if (_argonState === 'loading') {
        const elapsed = timestamp - _argonStartTime;
        const timeConstant = _argonEstDuration / 2.5;
        const ratio = 1 - Math.exp(-elapsed / timeConstant);
        _argonCurrentPercent = Math.min(95, 95 * ratio);

        if (bar) bar.style.width = _argonCurrentPercent.toFixed(1) + '%';
        if (pctText) pctText.textContent = Math.round(_argonCurrentPercent) + '%';

        if (_argonBackendFinished && elapsed >= MIN_ARGON_OVERLAY_DISPLAY_MS) {
            _argonState = 'finishing';
            _argonFinishStartTime = timestamp;
            _argonStartPercent = _argonCurrentPercent;
        }
    } else if (_argonState === 'finishing') {
        const finishElapsed = timestamp - _argonFinishStartTime;
        const FINISH_DURATION_MS = 400; // Animate to 100% in 400ms
        const tRatio = Math.min(1.0, finishElapsed / FINISH_DURATION_MS);
        
        // Ease-out cubic: f(t) = 1 - (1-t)^3
        const easeOutCubic = 1 - Math.pow(1 - tRatio, 3);
        _argonCurrentPercent = _argonStartPercent + (100 - _argonStartPercent) * easeOutCubic;

        if (bar) bar.style.width = _argonCurrentPercent.toFixed(1) + '%';
        if (pctText) pctText.textContent = Math.round(_argonCurrentPercent) + '%';

        if (tRatio >= 1.0) {
            _argonState = 'fade-wait';
            _argonFadeStartTime = timestamp;
        }
    } else if (_argonState === 'fade-wait') {
        const waitElapsed = timestamp - _argonFadeStartTime;
        if (waitElapsed >= 200) {
            _argonState = 'fading';
            _argonFadeStartTime = timestamp;
            if (shield) {
                shield.style.opacity = '0';
            }
        }
    } else if (_argonState === 'fading') {
        const fadeElapsed = timestamp - _argonFadeStartTime;
        if (fadeElapsed >= 300) {
            _argonState = 'idle';
            if (shield) {
                shield.classList.remove('active');
                shield.style.opacity = '';
            }
            if (bar) bar.style.width = '0%';
            if (pctText) pctText.textContent = '0%';
            _argonAnimationId = null;
            return;
        }
    }

    _argonAnimationId = requestAnimationFrame(updateArgonOverlay);
}

function hideArgonWorkOverlay() {
    _argonBackendFinished = true;
}

// 5. Apple Custom Select & Lang Switcher Popover Implementation
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('select.apple-select').forEach(select => {
        // Wrapper
        const wrapper = document.createElement('div');
        wrapper.className = 'apple-custom-select-wrapper';
        select.parentNode.insertBefore(wrapper, select);
        wrapper.appendChild(select);
        
        // Hide original
        select.style.display = 'none';

        // Unique Popover ID
        const popoverId = 'apple-select-' + Math.random().toString(36).substring(2, 11);

        // Trigger (Semantic Button)
        const trigger = document.createElement('button');
        trigger.type = 'button';
        trigger.className = 'apple-custom-select-trigger';
        trigger.setAttribute('popovertarget', popoverId);
        if (select.dataset.style === 'form') {
            trigger.classList.add('form-style');
            wrapper.classList.add('w-full');
        }
        const initialText = select.options[select.selectedIndex]?.text || '';
        trigger.innerHTML = `<span>${initialText}</span><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 12 12"><path d="M6 8L1 3h10z"/></svg>`;
        wrapper.appendChild(trigger);

        // Dropdown menu as popover
        const dropdown = document.createElement('div');
        dropdown.className = 'apple-custom-select-dropdown';
        dropdown.id = popoverId;
        dropdown.setAttribute('popover', 'auto');
        
        Array.from(select.options).forEach(opt => {
            const item = document.createElement('div');
            item.className = 'apple-custom-option' + (opt.selected ? ' selected' : '');
            item.dataset.value = opt.value;
            item.innerHTML = `<span>${opt.text}</span><svg class="check-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>`;
            
            item.addEventListener('click', (e) => {
                e.stopPropagation();
                select.value = opt.value;
                select.dispatchEvent(new Event('change'));
                
                trigger.querySelector('span').textContent = opt.text;
                dropdown.querySelectorAll('.apple-custom-option').forEach(el => el.classList.remove('selected'));
                item.classList.add('selected');
                
                dropdown.hidePopover();
            });
            dropdown.appendChild(item);
        });
        wrapper.appendChild(dropdown);

        const syncDropdownOpenState = (isOpen) => {
            wrapper.classList.toggle('open', isOpen);
            ['.settings-group', '.settings-section', '.form-group'].forEach(cls => {
                wrapper.closest(cls)?.classList.toggle('has-open-dropdown', isOpen);
            });
        };

        const positionDropdown = () => {
            const rect = trigger.getBoundingClientRect();
            const viewportMargin = 12;
            const dropdownGap = 8;
            const viewportWidth = document.documentElement.clientWidth;
            const viewportHeight = document.documentElement.clientHeight;
            const availableWidth = Math.max(180, viewportWidth - (viewportMargin * 2));
            const estimatedWidth = Math.min(Math.max(rect.width, dropdown.offsetWidth || 180), availableWidth);
            const left = Math.min(
                Math.max(viewportMargin, rect.left),
                Math.max(viewportMargin, viewportWidth - estimatedWidth - viewportMargin)
            );

            dropdown.style.minWidth = `${rect.width}px`;
            dropdown.style.maxWidth = `${availableWidth}px`;
            dropdown.style.left = `${left}px`;

            const availableBelow = viewportHeight - rect.bottom - dropdownGap - viewportMargin;
            const availableAbove = rect.top - dropdownGap - viewportMargin;
            const desiredHeight = dropdown.scrollHeight || dropdown.offsetHeight || 180;
            const shouldOpenAbove = desiredHeight > availableBelow && availableAbove > availableBelow;
            const availableHeight = Math.max(120, shouldOpenAbove ? availableAbove : availableBelow);
            const renderedHeight = Math.min(desiredHeight, availableHeight);
            const top = shouldOpenAbove
                ? Math.max(viewportMargin, rect.top - renderedHeight - dropdownGap)
                : Math.min(viewportHeight - viewportMargin, rect.bottom + dropdownGap);

            dropdown.style.maxHeight = `${availableHeight}px`;
            dropdown.style.top = `${top}px`;
            dropdown.style.transformOrigin = shouldOpenAbove ? 'bottom center' : 'top center';
        };

        const repositionOpenDropdown = () => {
            if (dropdown.matches(':popover-open')) positionDropdown();
        };

        // Position popovers in viewport coordinates; they render in the top layer.
        dropdown.addEventListener('beforetoggle', (e) => {
            if (e.newState === 'open') {
                syncDropdownOpenState(true);
                positionDropdown();
                requestAnimationFrame(positionDropdown);
            } else {
                syncDropdownOpenState(false);
            }
        });

        window.addEventListener('resize', repositionOpenDropdown);
        window.addEventListener('scroll', repositionOpenDropdown, true);
    });

    // 6. Language Switcher Popover Dynamic Positioning
    const langDropdown = document.getElementById('lang-switcher-dropdown');
    if (langDropdown) {
        langDropdown.addEventListener('beforetoggle', (e) => {
            if (e.newState === 'open') {
                const btn = document.querySelector('.lang-btn');
                if (!btn) return;
                const rect = btn.getBoundingClientRect();
                const dropdownHeight = langDropdown.getBoundingClientRect().height || 180;
                const isCollapsed = document.body.classList.contains('sidebar-collapsed') || window.innerWidth <= 1200;

                if (isCollapsed) {
                    langDropdown.style.left = `${rect.right + 12 + window.scrollX}px`;
                    langDropdown.style.top = `${rect.bottom - dropdownHeight + window.scrollY}px`;
                } else {
                    langDropdown.style.left = `${rect.left + window.scrollX}px`;
                    langDropdown.style.top = `${rect.top - dropdownHeight - 8 + window.scrollY}px`;
                }
            }
        });
    }
});


/**
 * Global Notification System
 * @param {string} msg 
 * @param {string} type - info, error, success, warning
 */
function showNotification(msg, type = "info") {
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.style.cssText = 'position:fixed; bottom:2rem; right:2rem; z-index:9999; box-shadow:var(--shadow-lg); transition: all 0.3s ease;';
    alert.textContent = msg;
    document.body.appendChild(alert);
    
    // Smooth entry
    requestAnimationFrame(() => {
        alert.style.transform = 'translateY(0)';
        alert.style.opacity = '1';
    });

    setTimeout(() => {
        alert.style.opacity = '0';
        alert.style.transform = 'translateY(10px)';
        setTimeout(() => alert.remove(), 300);
    }, 4000);
}

window.showNotification = showNotification;
