// Paracci - Session & Messaging Logic (Hardened)

let currentMsgRawText = "";
let isMessageOpen = false;
let quietMode = localStorage.getItem('paracci_quiet_mode') === 'true';
let copyTimer = null;
let copiedClipboardTextPendingClear = false;
let clipboardClearInFlight = null;
let clipboardRetryPending = false;
let clipboardRetryTimeout = null;
let clipboardRetryShowSuccess = false;
let currentPreviewIds = new Set();
const MIN_SAFE_DOMPURIFY_VERSION = "3.1.3";
const MARKDOWN_FRAGMENT_HREF_RE = /^#[^\s"'<>]*$/;
const CLIPBOARD_CLEAR_DELAY_SECONDS = 30;
const CLIPBOARD_CLEAR_RETRY_WINDOW_MS = 30000;
const CLIPBOARD_NATIVE_API_WAIT_ATTEMPTS = 10;
const CLIPBOARD_NATIVE_API_WAIT_MS = 100;
let runtimeCapabilities = { has_native_window: false };
let capabilitiesPromise = null;

function previewWindowApiAvailable() {
    return typeof window.pywebview?.api?.open_preview_window === 'function';
}

async function loadRuntimeCapabilities({ force = false } = {}) {
    if (!force && capabilitiesPromise) return capabilitiesPromise;

    const url = window.PARACCI_CONFIG?.capabilities_url || '/api/capabilities';
    capabilitiesPromise = fetch(url, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
        cache: 'no-store'
    })
        .then(async response => {
            if (!response.ok) throw new Error(`Capabilities request failed: ${response.status}`);
            const data = await response.json();
            runtimeCapabilities = {
                has_native_window: data?.has_native_window === true
            };
            return runtimeCapabilities;
        })
        .catch(err => {
            console.warn('[Paracci] Capability detection failed:', err);
            runtimeCapabilities = { has_native_window: previewWindowApiAvailable() };
            return runtimeCapabilities;
        });

    return capabilitiesPromise;
}

function parseVersionParts(version) {
    return String(version || "")
        .split(".")
        .map(part => Number.parseInt(part, 10))
        .map(part => Number.isFinite(part) ? part : 0);
}

function compareVersions(left, right) {
    const leftParts = parseVersionParts(left);
    const rightParts = parseVersionParts(right);
    const maxLength = Math.max(leftParts.length, rightParts.length);
    for (let i = 0; i < maxLength; i += 1) {
        const leftPart = leftParts[i] || 0;
        const rightPart = rightParts[i] || 0;
        if (leftPart !== rightPart) return leftPart > rightPart ? 1 : -1;
    }
    return 0;
}

function requireSafeDompurify() {
    const sanitizer = window.DOMPurify;
    if (!sanitizer || typeof sanitizer.sanitize !== "function") {
        throw new Error("DOMPurify is not available.");
    }
    if (compareVersions(sanitizer.version, MIN_SAFE_DOMPURIFY_VERSION) < 0) {
        throw new Error(`DOMPurify ${sanitizer.version || "unknown"} is below ${MIN_SAFE_DOMPURIFY_VERSION}.`);
    }
    return sanitizer;
}

function sanitizeRenderedMarkdown(rawHtml, sanitizer) {
    return sanitizer.sanitize(rawHtml, {
        ALLOWED_URI_REGEXP: MARKDOWN_FRAGMENT_HREF_RE,
        FORBID_ATTR: ['target']
    });
}

function renderSafeMarkdown(text, sanitizer = requireSafeDompurify()) {
    const rawHtml = marked.parse(String(text ?? ''));
    return sanitizeRenderedMarkdown(rawHtml, sanitizer);
}

document.addEventListener('DOMContentLoaded', () => {
    const configEl = document.getElementById('paracci-config');
    if (configEl) {
        window.PARACCI_CONFIG = {
            sid: configEl.dataset.sid,
            open_url: configEl.dataset.openUrl,
            cache_clear_url: configEl.dataset.cacheClearUrl,
            auto_download: configEl.dataset.autoDownload === 'true',
            export_url: configEl.dataset.exportUrl,
            export_filename: configEl.dataset.exportFilename,
            prepare_preview_url: configEl.dataset.preparePreviewUrl,
            capabilities_url: configEl.dataset.capabilitiesUrl,
            armor_text: configEl.dataset.armorText,
            open_error: configEl.dataset.openError,
            preview_label: configEl.dataset.previewLabel || 'Preview'
        };
    }

    loadRuntimeCapabilities();

    // 1. Initial UI Setup
    const qm = document.getElementById('quiet-mode-checkbox');
    if (qm) qm.checked = quietMode;

    const msgContainer = document.getElementById('message-view-container');
    if (msgContainer) msgContainer.style.display = 'none';

    // 2. Drop Zone Logic
    setupAttachmentDropZone();
    setupSessionDropZone();

    // 3. Global Message Form Handling
    setupForms();
    setupTemplateEventBindings();

    // 4. Dismiss Warning if already acknowledged
    if (window.PARACCI_CONFIG?.sid) {
        if (localStorage.getItem("dismiss_y_" + window.PARACCI_CONFIG.sid)) {
            const el = document.getElementById("y-responder-warning");
            if (el) el.style.display = "none";
        }
    }

    const openFileInput = document.getElementById('paracci_file');
    if (openFileInput) {
        openFileInput.addEventListener('change', () => {
            if (openFileInput.files?.length) {
                const label = document.getElementById('file-label');
                if (label) label.textContent = openFileInput.files[0].name;
                const nativeFileId = document.getElementById('open-native-file-id');
                if (nativeFileId) nativeFileId.value = '';
                openFileInput.required = true;
            }
        });
    }

    // 5. Auto-download after config initialization
    if (window.PARACCI_CONFIG?.auto_download && window.pywebview?.api) {
        triggerAutoDownload();
    }
});

// Pywebview ready event to handle async API injection
window.addEventListener('pywebviewready', () => {
    runtimeCapabilities = { has_native_window: true };
    loadRuntimeCapabilities({ force: true });
    if (window.PARACCI_CONFIG?.auto_download) {
        triggerAutoDownload();
    }
});

function setupAttachmentDropZone() {
    const attDrop = document.getElementById('attachment-drop-zone');
    const attInput = document.getElementById('attachments');
    if (attDrop && attInput) {
        attDrop.onclick = async () => {
            if (window.pywebview?.api?.select_attachments && window.stageNativeAttachmentsFromPicker) {
                try {
                    await window.stageNativeAttachmentsFromPicker();
                } catch (err) {
                    const message = err?.message ?? String(err);
                    showNotification(message || window.PARACCI_I18N?.drop_failed || 'Attachment could not be staged.', 'error');
                    const isExpected = message.includes('50MB') || message.includes('limit') || message.includes('size');
                    if (!isExpected) {
                        console.error('[Paracci] Native attachment picker failed:', err);
                    }
                }
                return;
            }
            attInput.click();
        };
        attDrop.addEventListener('dragover', (e) => {
            e.preventDefault();
            attDrop.classList.add('highlight');
        });
        attDrop.addEventListener('dragleave', (e) => {
            e.preventDefault();
            attDrop.classList.remove('highlight');
        });
        attDrop.addEventListener('drop', (e) => {
            e.preventDefault();
            attDrop.classList.remove('highlight');
            if (e.dataTransfer.files?.length) {
                attInput.files = e.dataTransfer.files;
                updateAttachmentBadge();
            }
        });
        attInput.onchange = updateAttachmentBadge;
    }
}

function setupSessionDropZone() {
    const sessionDrop = document.getElementById('session-drop-zone');
    if (sessionDrop) {
        sessionDrop.addEventListener('dragover', (e) => {
            e.preventDefault();
            sessionDrop.classList.add('highlight');
        });
        sessionDrop.addEventListener('dragleave', (e) => {
            e.preventDefault();
            sessionDrop.classList.remove('highlight');
        });
        sessionDrop.addEventListener('drop', (e) => {
            e.preventDefault();
            sessionDrop.classList.remove('highlight');
        });
    }
}

function setupTemplateEventBindings() {
    document.getElementById('safety-mini-badge')?.addEventListener('click', () => window.toggleSafetyDetails?.());

    const responderDrop = document.getElementById('responder-drop-area');
    const responderInput = document.getElementById('responder-input');
    responderDrop?.addEventListener('click', () => responderInput?.click());
    responderInput?.addEventListener('change', () => {
        const nativeFileId = document.getElementById('responder-native-file-id');
        if (nativeFileId) nativeFileId.value = '';
        responderInput.required = true;
        requestFormSubmit(responderInput.form);
    });

    document.querySelectorAll('[data-manual-download-url]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            handleManualDownload(link.dataset.manualDownloadUrl, link.dataset.manualDownloadFilename || 'download.paracci');
        });
    });

    document.getElementById('dismiss-y-warning')?.addEventListener('click', (e) => {
        window.dismissYWarning?.(e.currentTarget.dataset.sessionId || window.PARACCI_CONFIG?.sid || '');
    });
    document.getElementById('session-drop-zone')?.addEventListener('click', () => {
        document.getElementById('paracci_file')?.click();
    });
    document.getElementById('exit-modal-cancel')?.addEventListener('click', () => window.cancelClose?.());
    document.getElementById('exit-modal-confirm')?.addEventListener('click', () => window.confirmClose?.());

    document.getElementById('quiet-mode-checkbox')?.addEventListener('change', (e) => {
        window.toggleQuietMode?.(e.target.checked);
    });
    document.getElementById('btn-copy-msg')?.addEventListener('click', () => {
        window.handleSecureCopy?.();
    });
    document.getElementById('btn-close-msg')?.addEventListener('click', () => {
        window.handleCloseClick?.();
    });
}

function updateAttachmentBadge() {
    const attInput = document.getElementById('attachments');
    const container = document.getElementById('selected-attachments-container');
    const list = document.getElementById('selected-attachments-list');
    if (!container || !list) return;

    list.innerHTML = '';

    const browserFiles = attInput?.files ? Array.from(attInput.files) : [];
    const nativeFiles = window.PARACCI_STAGED_ATTACHMENTS || [];

    const totalCount = browserFiles.length + nativeFiles.length;

    if (totalCount === 0) {
        container.style.display = 'none';
        return;
    }

    container.style.display = 'block';

    function formatFileSize(bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
        if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + " MB";
        return (bytes / (1024 * 1024 * 1024)).toFixed(2) + " GB";
    }

    // 1. Render Browser-selected files
    browserFiles.forEach((file, index) => {
        const itemDiv = document.createElement('div');
        itemDiv.className = 'selected-attachment-item';

        const infoDiv = document.createElement('div');
        infoDiv.className = 'selected-attachment-info';

        const nameDiv = document.createElement('div');
        nameDiv.className = 'selected-attachment-name';
        nameDiv.title = file.name;
        nameDiv.textContent = file.name;

        const sizeDiv = document.createElement('div');
        sizeDiv.className = 'selected-attachment-size';
        sizeDiv.textContent = formatFileSize(file.size);

        infoDiv.appendChild(nameDiv);
        infoDiv.appendChild(sizeDiv);

        const removeBtn = document.createElement('button');
        removeBtn.type = 'button';
        removeBtn.className = 'btn-selected-attachment-remove';
        removeBtn.title = 'Remove file';
        removeBtn.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" width="14" height="14">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
        `;
        removeBtn.onclick = (e) => {
            e.preventDefault();
            removeBrowserAttachment(index);
        };

        itemDiv.appendChild(infoDiv);
        itemDiv.appendChild(removeBtn);

        list.appendChild(itemDiv);
    });

    // 2. Render Native staged files
    nativeFiles.forEach((file) => {
        const itemDiv = document.createElement('div');
        itemDiv.className = 'selected-attachment-item';

        const infoDiv = document.createElement('div');
        infoDiv.className = 'selected-attachment-info';

        const nameDiv = document.createElement('div');
        nameDiv.className = 'selected-attachment-name';
        nameDiv.title = file.filename;
        nameDiv.textContent = file.filename;

        const sizeDiv = document.createElement('div');
        sizeDiv.className = 'selected-attachment-size';
        sizeDiv.textContent = formatFileSize(file.size || 0);

        infoDiv.appendChild(nameDiv);
        infoDiv.appendChild(sizeDiv);

        const removeBtn = document.createElement('button');
        removeBtn.type = 'button';
        removeBtn.className = 'btn-selected-attachment-remove';
        removeBtn.title = 'Remove file';
        removeBtn.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" width="14" height="14">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
        `;
        removeBtn.onclick = (e) => {
            e.preventDefault();
            removeNativeAttachment(file.id);
        };

        itemDiv.appendChild(infoDiv);
        itemDiv.appendChild(removeBtn);

        list.appendChild(itemDiv);
    });
}

function removeBrowserAttachment(index) {
    const input = document.getElementById('attachments');
    if (!input || !input.files) return;
    const dt = new DataTransfer();
    const files = input.files;
    for (let i = 0; i < files.length; i++) {
        if (i !== index) {
            dt.items.add(files[i]);
        }
    }
    input.files = dt.files;
    updateAttachmentBadge();
}

async function removeNativeAttachment(id) {
    try {
        fetch(window.PARACCI_CONFIG?.cache_clear_url || '/api/sensitive-cache/clear', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ preview_ids: [], staged_attachment_ids: [id] })
        }).catch(err => console.warn('[Paracci] Staged attachment cache clear failed:', err));
    } catch (e) {
        console.error('[Paracci] Error clearing attachment from backend:', e);
    }

    window.PARACCI_STAGED_ATTACHMENTS = (window.PARACCI_STAGED_ATTACHMENTS || [])
        .filter(att => att.id !== id);

    const hidden = document.getElementById('staged_attachment_ids');
    if (hidden) {
        hidden.value = window.PARACCI_STAGED_ATTACHMENTS.map(att => att.id).join(',');
    }

    updateAttachmentBadge();
}

function setupForms() {
    // SEAL FORM
    document.getElementById('seal-form')?.addEventListener('submit', async function (e) {
        e.preventDefault();
        const btn = document.getElementById('seal-submit');
        const origText = btn.textContent;
        btn.disabled = true;
        btn.textContent = window.PARACCI_CONFIG?.armor_text || 'Processing...';
        if (window.showArgonWorkOverlay) window.showArgonWorkOverlay('seal');

        try {
            const response = await fetch(this.action, { method: 'POST', body: new FormData(this) });
            if (response.redirected) {
                window.location.href = response.url;
                return;
            }
            if (!response.ok) throw new Error(window.PARACCI_I18N?.server_error || 'Server error');

            const blob = await response.blob();
            const cd = response.headers.get('Content-Disposition');
            let filename = 'message.paracci';
            if (cd?.includes('filename=')) {
                filename = cd.split('filename=')[1].replace(/"/g, '');
            }

            if (window.pywebview?.api?.save_file_silent) {
                const reader = new FileReader();
                reader.onloadend = async () => {
                    let b64 = "";
                    try {
                        b64 = String(reader.result || '').split(',')[1] || '';
                        const savedPath = await window.pywebview.api.save_file_silent(b64, filename);
                        if (savedPath) {
                            if (window.showDownloadNotification) window.showDownloadNotification(filename, savedPath);
                            this.reset();
                            if (window.clearStagedAttachments) window.clearStagedAttachments();
                            document.getElementById('allow_download').checked = false;
                            updateAttachmentBadge();
                        }
                    } finally {
                        b64 = "";
                    }
                };
                reader.readAsDataURL(blob);
            } else {
                // Browser download fallback
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                a.click();
                window.URL.revokeObjectURL(url);
                this.reset();
                if (window.clearStagedAttachments) window.clearStagedAttachments();
                document.getElementById('allow_download').checked = false;
                updateAttachmentBadge();
            }
        } catch (err) {
            console.error('[Paracci] Seal error:', err);
            showNotification(window.PARACCI_I18N?.processing_failed || "Processing failed.", "error");
        } finally {
            btn.disabled = false;
            btn.textContent = origText;
            if (window.hideArgonWorkOverlay) window.hideArgonWorkOverlay();
        }
    });

    // OPEN MESSAGE FORM
    document.getElementById('open-message-form')?.addEventListener('submit', async function (e) {
        e.preventDefault();

        const fileInput = document.getElementById('paracci_file');
        const nativeFileId = document.getElementById('open-native-file-id');

        // Manual validation since hidden required inputs cause focus errors
        if ((!fileInput || !fileInput.files || fileInput.files.length === 0) && (!nativeFileId || !nativeFileId.value)) {
            const errorContainer = document.getElementById('dynamic-error-container');
            clearElement(errorContainer);
            appendAlert(errorContainer, 'error', window.PARACCI_I18N?.error || 'Error', window.PARACCI_I18N?.select_file_error || 'Please select a file to open.');
            return;
        }

        const btn = document.getElementById('btn-open-msg');
        const origText = btn.textContent;
        btn.disabled = true;
        btn.textContent = window.PARACCI_CONFIG?.armor_text || 'Processing...';
        if (window.showArgonWorkOverlay) window.showArgonWorkOverlay('open');

        const errorContainer = document.getElementById('dynamic-error-container');
        clearElement(errorContainer);

        try {
            const url = window.PARACCI_CONFIG?.open_url;
            const response = await fetch(
                url + (url.includes('?') ? '&' : '?') + "ajax=1",
                { method: 'POST', body: new FormData(this), headers: { 'X-Requested-With': 'XMLHttpRequest' } }
            );
            const data = await response.json();

            if (!data.success) {
                const errLabel = window.PARACCI_I18N?.error || 'Error';
                appendAlert(errorContainer, 'error', `${errLabel}:`, data.error);
                return;
            }

            renderDecryptedMessage(data);
            isMessageOpen = true;
            this.reset();
            const nativeFileId = document.getElementById('open-native-file-id');
            if (nativeFileId) nativeFileId.value = '';
            const fileInput = document.getElementById('paracci_file');
            if (fileInput) fileInput.required = true;
            document.getElementById('message-view-container').scrollIntoView({ behavior: 'smooth' });

        } catch (err) {
            console.error('[Paracci] Open error:', err);
            appendAlert(errorContainer, 'error', '', window.PARACCI_I18N?.msg_not_processed || 'Message could not be processed.');
        } finally {
            btn.disabled = false;
            btn.textContent = origText;
            if (window.hideArgonWorkOverlay) window.hideArgonWorkOverlay();
        }
    });

    // RESPONDER FORM
    document.getElementById('responder-form')?.addEventListener('submit', function () {
        if (window.showArgonWorkOverlay) window.showArgonWorkOverlay('finalize');
    });
}

function clearElement(el) {
    if (el) el.replaceChildren();
}

function appendAlert(container, level, label, message) {
    if (!container) return;
    const alert = document.createElement('div');
    alert.className = `alert alert-${level}`;
    if (label) {
        const strong = document.createElement('strong');
        strong.textContent = label;
        alert.appendChild(strong);
        alert.appendChild(document.createTextNode(' '));
    }
    alert.appendChild(document.createTextNode(String(message ?? '')));
    container.appendChild(alert);
}

function clearServerSensitiveCaches({ keepalive = false } = {}) {
    const previewIds = Array.from(currentPreviewIds);
    currentPreviewIds.clear();
    if (!previewIds.length) return Promise.resolve(false);

    const url = window.PARACCI_CONFIG?.cache_clear_url || '/api/sensitive-cache/clear';
    const payload = JSON.stringify({ preview_ids: previewIds, staged_attachment_ids: [] });
    return fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload,
        keepalive
    }).catch(err => {
        console.warn('[Paracci] Sensitive cache clear failed:', err);
        return false;
    });
}

function clearOpenMessageState({ clearServer = true, keepalive = false } = {}) {
    if (clearServer) clearServerSensitiveCaches({ keepalive });
    currentMsgRawText = "";
    window._currentMsgCanCopy = false;
    isMessageOpen = false;
    if (copyTimer) {
        clearInterval(copyTimer);
        copyTimer = null;
    }
    if (copiedClipboardTextPendingClear) {
        void requestClipboardClear({ showSuccess: false });
    }

    clearElement(document.getElementById('rendered-message'));
    clearElement(document.getElementById('msg-security-report'));
    clearElement(document.getElementById('attachments-list-items'));

    const messageContainer = document.getElementById('message-view-container');
    if (messageContainer) messageContainer.style.display = 'none';
    const attachmentsContainer = document.getElementById('attachments-container');
    if (attachmentsContainer) attachmentsContainer.style.display = 'none';
    const copyBtn = document.getElementById('btn-copy-msg');
    if (copyBtn) {
        copyBtn.style.display = 'none';
        copyBtn.disabled = false;
        copyBtn.textContent = window.PARACCI_I18N?.copy_protection_btn || 'Copy (30s auto-clear)';
    }
}

function attachmentUrl(att, key, fallbackPrefix) {
    const direct = att?.[key];
    if (typeof direct === 'string' && direct.startsWith('/') && !direct.startsWith('//')) return direct;
    const pid = encodeURIComponent(String(att?.pid || ''));
    if (!pid) return '';
    return `${fallbackPrefix}/${pid}${key === 'download_url' ? '/download' : ''}`;
}

function renderDecryptedMessage(data) {
    const container = document.getElementById('message-view-container');
    if (!container) return;

    clearOpenMessageState();
    currentMsgRawText = data.text;
    (data.attachments || []).forEach(att => {
        if (att?.pid) currentPreviewIds.add(String(att.pid));
    });
    
    // Security Report
    const securityDiv = document.getElementById('msg-security-report');
    if (securityDiv) {
        clearElement(securityDiv);
        securityDiv.style.display = 'none';
        if (data.security_report && !data.security_report.is_safe) {
            securityDiv.style.display = 'block';
            data.security_report.risks.forEach(risk => {
                const warnLabel = window.PARACCI_I18N?.security_warning || 'SECURITY WARNING:';
                appendAlert(securityDiv, 'error', warnLabel, risk?.target || risk);
            });
        }
    }

    // Message Content
    try {
        const sanitizer = requireSafeDompurify();
        document.getElementById('rendered-message').innerHTML = renderSafeMarkdown(data.text, sanitizer);
    } catch (e) {
        document.getElementById('rendered-message').textContent = data.text;
    }

    // Badges & Alerts
    document.getElementById('msg-badge-burn').style.display = data.single_use ? 'inline-flex' : 'none';
    const ttlBadge = document.getElementById('msg-badge-ttl');
    if (data.expire_at > 0) {
        ttlBadge.style.display = 'inline-block';
        document.getElementById('msg-time-left').textContent = data.time_left;
    } else {
        ttlBadge.style.display = 'none';
    }

    const canDownload = !!data.allow_download;
    const msgContainer = document.getElementById('message-view-container');
    if (msgContainer) {
        msgContainer.setAttribute('data-allow-download', canDownload ? 'true' : 'false');
    }
    document.getElementById('allow-download-alert').style.display = canDownload ? 'flex' : 'none';
    document.getElementById('no-download-alert').style.display = canDownload ? 'none' : 'flex';
    document.getElementById('single-use-alert').style.display = data.single_use ? 'flex' : 'none';
    
    const copyBtn = document.getElementById('btn-copy-msg');
    if (copyBtn) copyBtn.style.display = canDownload ? 'inline-flex' : 'none';
    window._currentMsgCanCopy = canDownload;
    
    // Attachments
    const attList = document.getElementById('attachments-list-items');
    if (attList) {
        clearElement(attList);
        if (data.attachments?.length) {
            document.getElementById('attachments-container').style.display = 'block';
            data.attachments.forEach(att => {
                const item = document.createElement('div');
                item.className = 'attachment-item';
                const info = document.createElement('div');
                info.className = 'attachment-info';
                const name = document.createElement('div');
                name.className = 'attachment-name';
                name.textContent = att.filename || 'attachment.bin';
                info.appendChild(name);

                const actions = document.createElement('div');
                actions.className = 'attachment-actions';

                const previewRef = String(att?.pid || '');
                const previewBtn = document.createElement('button');
                previewBtn.type = 'button';
                previewBtn.className = 'btn-attachment';
                previewBtn.textContent = window.PARACCI_I18N?.preview_label || 'Preview';
                previewBtn.disabled = !previewRef;
                previewBtn.addEventListener('click', () => handleAttachmentPreview(previewRef, previewBtn));
                actions.appendChild(previewBtn);

                if (data.allow_download) {
                    const downloadUrl = attachmentUrl(att, 'download_url', '/preview');
                    const downloadBtn = document.createElement('button');
                    downloadBtn.type = 'button';
                    downloadBtn.className = 'btn-attachment';
                    downloadBtn.textContent = window.PARACCI_I18N?.download || 'Download';
                    downloadBtn.disabled = !downloadUrl;
                    downloadBtn.addEventListener('click', () => handleAttachmentDownload(downloadUrl, att.filename || 'attachment.bin'));
                    actions.appendChild(downloadBtn);
                }

                item.appendChild(info);
                item.appendChild(actions);
                attList.appendChild(item);
            });
        } else {
            document.getElementById('attachments-container').style.display = 'none';
        }
    }

    // Metadata
    document.getElementById('msg-evo-step').textContent = data.evo_step;
    document.getElementById('msg-id-short').textContent = data.msg_id_hex.substring(0, 16);
    
    container.style.display = 'block';
}

function cancelClipboardClearRetry() {
    if (clipboardRetryTimeout) {
        clearTimeout(clipboardRetryTimeout);
        clipboardRetryTimeout = null;
    }
    window.removeEventListener('focus', retryPendingClipboardClear);
    document.removeEventListener('visibilitychange', retryPendingClipboardClear);
    clipboardRetryPending = false;
    clipboardRetryShowSuccess = false;
}

function clipboardPageCanWrite() {
    return document.visibilityState === 'visible'
        && (typeof document.hasFocus !== 'function' || document.hasFocus());
}

async function getNativeClipboardApiForSecureOperation() {
    let api = window.pywebview?.api;
    if (typeof api?.copy_and_clear === 'function') return api;

    const capabilities = await loadRuntimeCapabilities();
    if (!capabilities?.has_native_window) return null;

    for (let attempt = 0; attempt < CLIPBOARD_NATIVE_API_WAIT_ATTEMPTS; attempt += 1) {
        await new Promise(resolve => setTimeout(resolve, CLIPBOARD_NATIVE_API_WAIT_MS));
        api = window.pywebview?.api;
        if (typeof api?.copy_and_clear === 'function') return api;
    }
    throw new Error('Native clipboard API is unavailable.');
}

function reportClipboardClearFailure() {
    cancelClipboardClearRetry();
    showNotification(
        window.PARACCI_I18N?.clipboard_clear_failed
            || 'Clipboard could not be cleared. Replace or clear it manually now.',
        'error'
    );
}

function scheduleClipboardClearRetry({ showSuccess }) {
    cancelClipboardClearRetry();
    clipboardRetryPending = true;
    clipboardRetryShowSuccess = showSuccess;
    window.addEventListener('focus', retryPendingClipboardClear);
    document.addEventListener('visibilitychange', retryPendingClipboardClear);
    clipboardRetryTimeout = setTimeout(() => {
        if (!clipboardRetryPending) return;
        reportClipboardClearFailure();
    }, CLIPBOARD_CLEAR_RETRY_WINDOW_MS);
}

async function retryPendingClipboardClear() {
    if (!clipboardRetryPending || !clipboardPageCanWrite()) return;
    const showSuccess = clipboardRetryShowSuccess;
    cancelClipboardClearRetry();
    await requestClipboardClear({ allowBrowserRetry: false, showSuccess });
}

async function performClipboardClear({ allowBrowserRetry = true, showSuccess = false } = {}) {
    let usedBrowserClipboard = false;
    try {
        const nativeApi = await getNativeClipboardApiForSecureOperation();
        if (nativeApi) {
            const success = await nativeApi.copy_and_clear('', 0);
            if (!success) throw new Error('Native clipboard clear failed.');
        } else {
            if (typeof navigator.clipboard?.writeText !== 'function') {
                throw new Error('Browser clipboard API is unavailable.');
            }
            usedBrowserClipboard = true;
            await navigator.clipboard.writeText('');
        }
        cancelClipboardClearRetry();
        copiedClipboardTextPendingClear = false;
        if (showSuccess) {
            showNotification(window.PARACCI_I18N?.clipboard_cleared || 'Clipboard cleared.');
        }
        return true;
    } catch (err) {
        console.warn('[Paracci] Clipboard clear failed:', err);
        if (usedBrowserClipboard && allowBrowserRetry) {
            scheduleClipboardClearRetry({ showSuccess });
        } else {
            reportClipboardClearFailure();
        }
        return false;
    }
}

function requestClipboardClear(options = {}) {
    if (clipboardClearInFlight) return clipboardClearInFlight;
    clipboardClearInFlight = performClipboardClear(options)
        .finally(() => {
            clipboardClearInFlight = null;
        });
    return clipboardClearInFlight;
}

function startClipboardClearCountdown(btn) {
    let timeLeft = CLIPBOARD_CLEAR_DELAY_SECONDS;
    if (btn) btn.disabled = true;
    if (copyTimer) clearInterval(copyTimer);
    copyTimer = setInterval(() => {
        timeLeft--;
        if (btn) {
            const pattern = window.PARACCI_I18N?.clearing_clipboard || 'Clearing clipboard ({s}s)';
            btn.textContent = pattern.replace('{s}', timeLeft);
        }
        if (timeLeft <= 0) {
            clearInterval(copyTimer);
            copyTimer = null;
            if (btn) {
                btn.textContent = window.PARACCI_I18N?.copy_protection_btn || 'Copy (30s auto-clear)';
                btn.disabled = false;
            }
            void requestClipboardClear({ showSuccess: true });
        }
    }, 1000);
}

async function handleSecureCopy() {
    if (!currentMsgRawText || !window._currentMsgCanCopy) return;

    cancelClipboardClearRetry();
    let success = false;
    let usedBrowserClipboard = false;
    try {
        const nativeApi = await getNativeClipboardApiForSecureOperation();
        if (nativeApi) {
            success = await nativeApi.copy_and_clear(currentMsgRawText, CLIPBOARD_CLEAR_DELAY_SECONDS);
        } else {
            if (typeof navigator.clipboard?.writeText !== 'function') {
                throw new Error('Browser clipboard API is unavailable.');
            }
            await navigator.clipboard.writeText(currentMsgRawText);
            success = true;
            usedBrowserClipboard = true;
        }
    } catch (err) {
        console.error('[Paracci] Clipboard write error:', err);
        success = false;
    }

    if (!success) {
        showNotification(window.PARACCI_I18N?.clipboard_failed_locked || "Clipboard access failed. It might be locked by another application.", "error");
        return;
    }

    copiedClipboardTextPendingClear = true;
    const btn = document.getElementById('btn-copy-msg');
    startClipboardClearCountdown(btn);
    showNotification(window.PARACCI_I18N?.text_copied_notify || 'Text copied. Clipboard will clear in 30 seconds.');
    if (usedBrowserClipboard) {
        showNotification(
            window.PARACCI_I18N?.clipboard_browser_history_warning
                || 'Browser mode cannot prevent clipboard history storage. Clear operating-system clipboard history manually.',
            'warning'
        );
    }
}

async function handleManualDownload(url, filename) {
    try {
        if (window.showArgonWorkOverlay) window.showArgonWorkOverlay();
        const response = await fetch(url);
        if (!response.ok) throw new Error(window.PARACCI_I18N?.download_failed || 'Download failed');
        const blob = await response.blob();

        const api = window.pywebview?.api;
        if (api) {
            const reader = new FileReader();
            reader.onloadend = async () => {
                let b64 = "";
                try {
                    b64 = String(reader.result || '').split(',')[1] || '';
                    let savedPath = null;

                    // Always use silent background download if supported, notifying the user afterwards
                    if (api.save_file_silent) {
                        savedPath = await api.save_file_silent(b64, filename);
                        if (savedPath && window.showDownloadNotification) {
                            window.showDownloadNotification(filename, savedPath);
                        }
                    } else if (api.save_file) {
                        savedPath = await api.save_file(b64, filename);
                    }
                } finally {
                    b64 = "";
                    if (window.hideArgonWorkOverlay) window.hideArgonWorkOverlay();
                }
            };
            reader.readAsDataURL(blob);
        } else {
            // Browser Fallback (Legacy/Dev)
            const link = document.createElement('a');
            const objectUrl = URL.createObjectURL(blob);
            link.href = objectUrl;
            link.download = filename;
            link.click();
            URL.revokeObjectURL(objectUrl);
            if (window.hideArgonWorkOverlay) window.hideArgonWorkOverlay();
        }
    } catch (err) {
        console.error('Download error:', err);
        if (window.hideArgonWorkOverlay) window.hideArgonWorkOverlay();
    }
}

function triggerAutoDownload() {
    const config = window.PARACCI_CONFIG;
    if (!config?.auto_download) return;
    
    // Auto-trigger the download for session init file
    if (config.export_url && config.export_filename) {
        setTimeout(() => {
            handleManualDownload(config.export_url, config.export_filename);
        }, 800);
    }
}

function normalizeAttachmentTarget(target, forDownload = false) {
    const value = String(target || '');
    if (value.startsWith('/') && !value.startsWith('//')) return value;
    const pid = encodeURIComponent(value);
    return pid ? `/preview/${pid}${forDownload ? '/download' : ''}` : '';
}

async function handleAttachmentDownload(target, filename) {
    const url = normalizeAttachmentTarget(target, true);
    if (!url) return;
    await handleManualDownload(url, filename);
}

function attachmentPreviewRef(target) {
    const value = String(target || '').trim();
    if (!value) return '';
    if (!value.startsWith('/preview/')) return value;

    try {
        const path = new URL(value, window.location.href).pathname;
        const parts = path.split('/').filter(Boolean);
        return parts[0] === 'preview' && parts[1] ? decodeURIComponent(parts[1]) : '';
    } catch (err) {
        return '';
    }
}

function tokenPreviewUrl(token) {
    return `/preview/${encodeURIComponent(String(token || ''))}`;
}

function previewSleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function previewAuthHeaders() {
    for (let attempt = 0; attempt < 12; attempt += 1) {
        const security = window.ParacciSecurity;
        const token = security?.getLoopbackToken?.() || '';
        const csrf = security?.getCsrfToken?.() || '';
        if (token && csrf) {
            return {
                'X-Paracci-Token': token,
                'X-CSRF-Token': csrf
            };
        }
        await previewSleep(100);
    }
    throw new Error('Unauthorized.');
}

function showPreviewOpenError(message) {
    const errorContainer = document.getElementById('dynamic-error-container');
    if (errorContainer) {
        clearElement(errorContainer);
        appendAlert(
            errorContainer,
            'error',
            `${window.PARACCI_I18N?.error || 'Error'}:`,
            message || window.PARACCI_I18N?.server_error || 'Preview could not be opened.'
        );
        return;
    }
    showNotification(message || 'Preview could not be opened.', 'error');
}

async function prepareAttachmentPreview(attachmentRef) {
    const authHeaders = await previewAuthHeaders();
    const response = await fetch(window.PARACCI_CONFIG?.prepare_preview_url || '/api/prepare-preview', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            ...authHeaders
        },
        credentials: 'same-origin',
        body: JSON.stringify({ attachment_ref: attachmentRef })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(data?.error || window.PARACCI_I18N?.server_error || 'Preview could not be prepared.');
    }
    if (!data?.preview_token) {
        throw new Error(window.PARACCI_I18N?.server_error || 'Preview token is missing.');
    }
    return data;
}

async function getPreviewWindowApi() {
    const capabilities = await loadRuntimeCapabilities();
    if (!capabilities?.has_native_window) return null;

    let api = window.pywebview?.api;
    let attempts = 0;
    while (!api?.open_preview_window && attempts < 10) {
        await new Promise(resolve => setTimeout(resolve, 100));
        api = window.pywebview?.api;
        attempts++;
    }
    return api?.open_preview_window ? api : null;
}

async function openPreparedPreview(data) {
    const token = data.preview_token;
    const api = await getPreviewWindowApi();
    if (api) {
        try {
            await api.open_preview_window(
                token,
                data.filename || 'attachment.bin',
                data.mime_type || 'application/octet-stream',
                Number(data.file_size || 0)
            );
            return;
        } catch (err) {
            console.warn('[Paracci] Native preview window failed, falling back to browser tab:', err);
        }
    }

    window.open(tokenPreviewUrl(token), '_blank', 'width=1000,height=800');
}


// Global exposure
window.handleManualDownload = handleManualDownload;
window.handleSecureCopy = handleSecureCopy;
window.handleAttachmentDownload = handleAttachmentDownload;
window.triggerAutoDownload = triggerAutoDownload;
window.updateAttachmentBadge = updateAttachmentBadge;
window.toggleQuietMode = (v) => { quietMode = v; localStorage.setItem('paracci_quiet_mode', v); };
window.handleCloseClick = () => { 
    if (quietMode) {
        closeMessage(); 
    } else {
        const dialog = document.getElementById('exit-confirm-dialog');
        if (dialog) dialog.showModal();
    }
};
window.cancelClose = () => {
    const dialog = document.getElementById('exit-confirm-dialog');
    if (dialog) dialog.close();
};
window.confirmClose = () => { window.cancelClose?.(); closeMessage(); };
window.dismissYWarning = (sid) => {
    if (sid) localStorage.setItem("dismiss_y_" + sid, "true");
    const el = document.getElementById("y-responder-warning");
    if (el) el.style.display = "none";
};

window.toggleSafetyDetails = () => {
    const el = document.getElementById('safety-details');
    if (el) el.classList.toggle('hidden');
};

window.handleAttachmentPreview = async (target, button) => {
    const attachmentRef = attachmentPreviewRef(target);
    if (!attachmentRef) return;

    const previewButton = button instanceof HTMLButtonElement ? button : null;
    const originalText = previewButton?.textContent;
    if (previewButton) {
        previewButton.disabled = true;
        previewButton.textContent = 'Opening...';
    }

    try {
        const data = await prepareAttachmentPreview(attachmentRef);
        await openPreparedPreview(data);
    } catch (err) {
        console.error('[Paracci] Preview error:', err);
        showPreviewOpenError(err.message);
    } finally {
        if (previewButton) {
            previewButton.disabled = false;
            previewButton.textContent = originalText || window.PARACCI_I18N?.preview_label || 'Preview';
        }
    }
};

function closeMessage() {
    clearOpenMessageState();
    void requestClipboardClear({ showSuccess: false });
}

window.addEventListener('pagehide', () => {
    clearOpenMessageState({ keepalive: true });
});

window.addEventListener('beforeunload', () => {
    clearOpenMessageState({ keepalive: true });
});

// Phase 3: Global Drag & Drop prevention to prevent pywebview navigation leak
window.addEventListener('dragover', (e) => {
    e.preventDefault();
}, false);
window.addEventListener('drop', (e) => {
    e.preventDefault();
}, false);
