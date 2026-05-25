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
    initUpdatesPage();

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
let _updateStatusPollingStarted = false;
let _updatesPageStarted = false;
let _updatesAckVersion = '';
let _updatesManualCheckPending = false;
const UPDATE_MARKDOWN_FRAGMENT_HREF_RE = /^#[^\s"'<>]*$/;

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

function renderUpdateMarkdown(container, markdown) {
    if (!container) return;
    const text = String(markdown || '');
    container.hidden = !text;
    if (!text) {
        container.replaceChildren();
        return;
    }
    if (typeof window.marked?.parse !== 'function' || typeof window.DOMPurify?.sanitize !== 'function') {
        container.textContent = text;
        return;
    }
    try {
        const rawHtml = window.marked.parse(text);
        container.innerHTML = window.DOMPurify.sanitize(rawHtml, {
            ALLOWED_TAGS: [
                'a', 'p', 'br', 'strong', 'b', 'em', 'i', 'code', 'pre', 'blockquote',
                'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr',
                'table', 'thead', 'tbody', 'tr', 'th', 'td'
            ],
            ALLOWED_ATTR: ['href', 'title'],
            ALLOWED_URI_REGEXP: UPDATE_MARKDOWN_FRAGMENT_HREF_RE,
            FORBID_ATTR: ['style', 'target']
        });
    } catch (_err) {
        container.textContent = text;
    }
}

function formatReleaseDate(rawDate) {
    if (!rawDate) return '';
    const parsed = new Date(rawDate);
    if (Number.isNaN(parsed.getTime())) return '';
    return parsed.toLocaleDateString(document.documentElement.lang || undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function scheduleUpdatePoll(delay = 1000) {
    clearTimeout(_updatePollTimer);
    _updatePollTimer = setTimeout(fetchUpdateStatus, delay);
}

function startUpdateStatusPollingWhenAuthorized() {
    if (_updateStatusPollingStarted || !window.ParacciSecurity?.getLoopbackToken?.()) return;
    _updateStatusPollingStarted = true;
    window.removeEventListener('pywebviewready', startUpdateStatusPollingWhenAuthorized);
    window.removeEventListener('paracci:loopback-token-ready', startUpdateStatusPollingWhenAuthorized);
    fetchUpdateStatus();
}

async function fetchUpdateStatus() {
    try {
        const response = await fetch('/api/update/status', { cache: 'no-store' });
        if (!response.ok) return;
        const status = await response.json();
        renderUpdateBanner(status);
        renderUpdatesPageStatus(status);
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
        renderUpdatesPageStatus(status);
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
        signature_missing: ['update_error_signature_missing', 'This release is missing a signed update manifest. Automatic installation is unavailable.'],
        signature_failed: ['update_error_signature_failed', 'Update signature verification failed. Automatic installation was stopped.'],
        size_mismatch: ['update_error_size_mismatch', 'The downloaded file size did not match the release asset. Installation was stopped.'],
        browser_open_failed: ['update_error_browser_open_failed', 'Could not open the releases page.'],
        installer_missing: ['update_error_installer_missing', 'The verified installer is no longer available.']
    };
    if (status.error_code && errors[status.error_code]) {
        return updateString(...errors[status.error_code]);
    }
    if (status.state === 'downloading') return updateString('update_downloading', 'Downloading update...');
    if (status.state === 'verifying') return updateString('update_verifying', 'Verifying signed update manifest and installer checksum...');
    if (status.state === 'ready') {
        return `${updateString('update_verified', 'Signed update verified.')} ${updateString('update_ready', 'Ready to install. The application will close.')}`;
    }
    if (status.state === 'cancelled') return updateString('update_cancelled', 'Download cancelled.');
    return '';
}

function renderUpdateBanner(status) {
    _updateStatus = status;
    const banner = document.getElementById('update-banner');
    if (!banner) return;
    if (document.getElementById('updates-page')) {
        banner.hidden = true;
        return;
    }
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
    renderUpdateMarkdown(notes, status.release_notes);

    if (_updateAckVersion !== status.latest_version) {
        ack.checked = false;
        _updateAckVersion = status.latest_version;
    }
    warning.hidden = !status.protocol_warning;
    warningText.textContent = status.protocol_unknown
        ? updateString('update_protocol_unknown', 'This release does not provide session protocol compatibility information. After updating, you may need to establish new sessions with your contacts.')
        : updateString('update_protocol_warning', 'This update changes message and setup file formats. Upgrade both participants before exchanging new messages; unfinished setup exchanges must be restarted.');

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
    window.addEventListener('pywebviewready', startUpdateStatusPollingWhenAuthorized);
    window.addEventListener('paracci:loopback-token-ready', startUpdateStatusPollingWhenAuthorized);
    startUpdateStatusPollingWhenAuthorized();
}

function renderUpdatesPageStatus(status) {
    const page = document.getElementById('updates-page');
    if (!page || !status) return;
    _updateStatus = status;
    const currentVersion = document.getElementById('updates-current-version');
    const checkButton = document.getElementById('updates-check-btn');
    const summaryStatus = document.getElementById('updates-status-text');
    const panel = document.getElementById('updates-available-panel');
    const versionLine = document.getElementById('updates-version-line');
    const notes = document.getElementById('updates-release-notes');
    const warning = document.getElementById('updates-protocol-warning');
    const warningText = document.getElementById('updates-protocol-warning-text');
    const ack = document.getElementById('updates-protocol-ack');
    const primary = document.getElementById('updates-primary-btn');
    const cancel = document.getElementById('updates-cancel-btn');
    const progressPanel = document.getElementById('updates-progress-panel');
    const progressFill = document.getElementById('updates-progress-fill');
    const progressPercent = document.getElementById('updates-progress-percent');
    const size = document.getElementById('updates-download-size');
    const actionStatus = document.getElementById('updates-action-status');
    const busy = ['checking', 'downloading', 'verifying', 'installing'].includes(status.state);
    const hasRelease = Boolean(status.latest_version) && ['available', 'downloading', 'verifying', 'ready', 'failed', 'cancelled', 'installing'].includes(status.state);

    if (_updatesManualCheckPending && status.state !== 'checking') {
        _updatesManualCheckPending = false;
        if (!hasRelease && !['downloading', 'verifying', 'ready', 'installing'].includes(status.state)) {
            requestManualUpdateCheck();
            return;
        }
    }

    currentVersion.textContent = status.current_version || '-';
    checkButton.disabled = busy || status.state === 'ready';
    summaryStatus.classList.toggle('error', status.state === 'check_failed');
    if (status.state === 'checking') {
        summaryStatus.textContent = updateString('update_checking', 'Checking for updates...');
    } else if (status.state === 'check_failed') {
        summaryStatus.textContent = updateString('update_check_failed', 'Unable to check for updates right now.');
    } else if (hasRelease) {
        summaryStatus.textContent = updateString('update_available_title', 'Update available.');
    } else {
        summaryStatus.textContent = updateString('update_latest', 'You are running the latest version.');
    }

    panel.hidden = !hasRelease;
    if (!hasRelease) return;

    versionLine.textContent = updateString(
        'update_version_line',
        'Current {current} - New {latest}',
        { current: status.current_version, latest: status.latest_version }
    );
    renderUpdateMarkdown(notes, status.release_notes);
    if (_updatesAckVersion !== status.latest_version) {
        ack.checked = false;
        _updatesAckVersion = status.latest_version;
    }
    warning.hidden = !status.protocol_warning;
    warningText.textContent = status.protocol_unknown
        ? updateString('update_protocol_unknown', 'This release does not provide session protocol compatibility information. After updating, you may need to establish new sessions with your contacts.')
        : updateString('update_protocol_warning', 'This update changes message and setup file formats. Upgrade both participants before exchanging new messages; unfinished setup exchanges must be restarted.');
    const hasProgress = ['downloading', 'verifying', 'ready'].includes(status.state);
    progressPanel.hidden = !hasProgress;
    progressFill.style.width = `${Number(status.progress_percent || 0)}%`;
    progressPercent.textContent = `${Number(status.progress_percent || 0)}%`;
    const formattedSize = formatUpdateSize(status.size_bytes);
    size.textContent = formattedSize
        ? updateString('update_size', 'Size: {size}', { size: formattedSize })
        : '';
    const message = updateStatusMessage(status);
    actionStatus.textContent = message;
    actionStatus.hidden = !message;
    actionStatus.classList.toggle('error', Boolean(status.error_code));
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

async function requestManualUpdateCheck() {
    const page = document.getElementById('updates-page');
    if (!page) return;
    try {
        const response = await fetch(page.dataset.checkUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: '{}'
        });
        const status = await response.json();
        if (!response.ok && status.error_code !== 'update_busy') {
            _updatesManualCheckPending = false;
            renderUpdatesPageStatus({ state: 'check_failed', current_version: _updateStatus?.current_version || '', error_code: 'check_failed' });
            return;
        }
        _updatesManualCheckPending = !response.ok && status.error_code === 'update_busy' && status.state === 'checking';
        renderUpdatesPageStatus(status);
        if (status.state === 'checking') scheduleUpdatePoll(250);
    } catch (_err) {
        _updatesManualCheckPending = false;
        renderUpdatesPageStatus({ state: 'check_failed', current_version: _updateStatus?.current_version || '', error_code: 'check_failed' });
    }
}

async function fetchUpdateHistory() {
    const page = document.getElementById('updates-page');
    const list = document.getElementById('updates-history-list');
    if (!page || !list) return;
    try {
        const response = await fetch(page.dataset.historyUrl, { cache: 'no-store' });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error_code || 'history_unavailable');
        list.replaceChildren();
        if (!payload.releases?.length) {
            const empty = document.createElement('p');
            empty.className = 'updates-muted';
            empty.textContent = updateString('update_history_empty', 'No release history is available.');
            list.appendChild(empty);
            return;
        }
        payload.releases.forEach(release => {
            const details = document.createElement('details');
            details.className = 'updates-history-item';
            const summary = document.createElement('summary');
            const version = document.createElement('span');
            version.className = 'updates-history-version';
            version.textContent = `v${release.version}`;
            const date = document.createElement('span');
            date.className = 'updates-history-date';
            const formattedDate = formatReleaseDate(release.published_at);
            date.textContent = formattedDate
                ? updateString('update_published_on', 'Published {date}', { date: formattedDate })
                : '';
            summary.append(version, date);
            const notes = document.createElement('div');
            notes.className = 'updates-history-notes update-markdown';
            renderUpdateMarkdown(notes, release.release_notes);
            details.append(summary, notes);
            list.appendChild(details);
        });
    } catch (_err) {
        list.replaceChildren();
        const error = document.createElement('p');
        error.className = 'updates-muted';
        error.textContent = updateString('update_history_failed', 'Unable to load update history right now.');
        list.appendChild(error);
    }
}

function startUpdatesPageWhenAuthorized() {
    if (_updatesPageStarted || !window.ParacciSecurity?.getLoopbackToken?.()) return;
    _updatesPageStarted = true;
    window.removeEventListener('pywebviewready', startUpdatesPageWhenAuthorized);
    window.removeEventListener('paracci:loopback-token-ready', startUpdatesPageWhenAuthorized);
    requestManualUpdateCheck();
    fetchUpdateHistory();
}

function initUpdatesPage() {
    const page = document.getElementById('updates-page');
    if (!page) return;
    document.getElementById('updates-check-btn')?.addEventListener('click', requestManualUpdateCheck);
    document.getElementById('updates-protocol-ack')?.addEventListener('change', () => {
        if (_updateStatus) renderUpdatesPageStatus(_updateStatus);
    });
    document.getElementById('updates-cancel-btn')?.addEventListener('click', () => {
        postUpdateAction(page.dataset.cancelUrl);
    });
    document.getElementById('updates-primary-btn')?.addEventListener('click', async () => {
        if (_updateStatus?.state === 'ready') {
            if (window.pywebview?.api?.install_verified_update) {
                await window.pywebview.api.install_verified_update();
            } else {
                showNotification(updateString('update_error_installer_missing', 'Installer launch is unavailable.'), 'error');
            }
            return;
        }
        await postUpdateAction(page.dataset.downloadUrl, {
            acknowledge_protocol_warning: Boolean(document.getElementById('updates-protocol-ack')?.checked)
        });
    });
    window.addEventListener('pywebviewready', startUpdatesPageWhenAuthorized);
    window.addEventListener('paracci:loopback-token-ready', startUpdatesPageWhenAuthorized);
    startUpdatesPageWhenAuthorized();
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
