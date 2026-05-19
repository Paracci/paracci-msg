// Paracci Secure Messaging - Global Application Logic
// Security Hardening & UI Notifications

(function initParacciI18n() {
    const source = document.getElementById('paracci-i18n-json');
    if (!source) {
        window.PARACCI_I18N = window.PARACCI_I18N || {};
        return;
    }
    try {
        window.PARACCI_I18N = JSON.parse(source.textContent || '{}');
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

// 4. Argon2id Work Overlay Helpers
function showArgonWorkOverlay() {
    const shield = document.getElementById('argonWorkOverlay');
    if (shield) shield.classList.add('active');
}

function hideArgonWorkOverlay() {
    const shield = document.getElementById('argonWorkOverlay');
    if (shield) shield.classList.remove('active');
}

// 5. Apple Custom Select Implementation
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('select.apple-select').forEach(select => {
        // Wrapper
        const wrapper = document.createElement('div');
        wrapper.className = 'apple-custom-select-wrapper';
        select.parentNode.insertBefore(wrapper, select);
        wrapper.appendChild(select);
        
        // Hide original
        select.style.display = 'none';

        // Trigger
        const trigger = document.createElement('div');
        trigger.className = 'apple-custom-select-trigger';
        if (select.dataset.style === 'form') {
            trigger.classList.add('form-style');
            wrapper.classList.add('w-full');
        }
        const initialText = select.options[select.selectedIndex]?.text || '';
        trigger.innerHTML = `<span>${initialText}</span><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 12 12"><path d="M6 8L1 3h10z"/></svg>`;
        wrapper.appendChild(trigger);

        // Dropdown menu
        const dropdown = document.createElement('div');
        dropdown.className = 'apple-custom-select-dropdown';
        
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
                
                wrapper.classList.remove('open');
                ['.settings-group', '.settings-section', '.form-group'].forEach(cls => {
                    wrapper.closest(cls)?.classList.remove('has-open-dropdown');
                });
            });
            dropdown.appendChild(item);
        });
        wrapper.appendChild(dropdown);

        // Toggle on click
        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            
            // Close other elements
            closeAllPopovers(wrapper);

            const willOpen = !wrapper.classList.contains('open');
            wrapper.classList.toggle('open');
            
            ['.settings-group', '.settings-section', '.form-group'].forEach(cls => {
                wrapper.closest(cls)?.classList.toggle('has-open-dropdown', willOpen);
            });
        });
    });

    // 6. Language Switcher Click-to-Toggle
    document.querySelectorAll('.lang-switcher').forEach(switcher => {
        const btn = switcher.querySelector('.lang-btn');
        if (btn) {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                closeAllPopovers(switcher);
                switcher.classList.toggle('open');
            });
        }
    });

    function closeAllPopovers(except = null) {
        // Close Selects
        document.querySelectorAll('.apple-custom-select-wrapper').forEach(w => {
            if (w !== except) {
                w.classList.remove('open');
                ['.settings-group', '.settings-section', '.form-group'].forEach(cls => {
                    w.closest(cls)?.classList.remove('has-open-dropdown');
                });
            }
        });
        // Close Lang Switchers
        document.querySelectorAll('.lang-switcher').forEach(s => {
            if (s !== except) s.classList.remove('open');
        });
    }

    // Close on outside click
    document.addEventListener('click', () => closeAllPopovers());
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

