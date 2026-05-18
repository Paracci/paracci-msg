// Paracci - Session & Messaging Logic (Hardened)

let currentMsgRawText = "";
let isMessageOpen = false;
let quietMode = localStorage.getItem('paracci_quiet_mode') === 'true';
let copyTimer = null;

document.addEventListener('DOMContentLoaded', () => {
    const configEl = document.getElementById('paracci-config');
    if (configEl) {
        window.PARACCI_CONFIG = {
            sid: configEl.dataset.sid,
            open_url: configEl.dataset.openUrl,
            auto_download: configEl.dataset.autoDownload === 'true',
            export_url: configEl.dataset.exportUrl,
            export_filename: configEl.dataset.exportFilename,
            armor_text: configEl.dataset.armorText,
            open_error: configEl.dataset.openError,
            preview_label: configEl.dataset.previewLabel || 'Preview'
        };
    }

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
                const nativePath = document.getElementById('open-native-path');
                if (nativePath) nativePath.value = '';
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
    if (window.PARACCI_CONFIG?.auto_download) {
        triggerAutoDownload();
    }
});

function setupAttachmentDropZone() {
    const attDrop = document.getElementById('attachment-drop-zone');
    const attInput = document.getElementById('attachments');
    if (attDrop && attInput) {
        attDrop.onclick = () => attInput.click();
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
        const nativePath = document.getElementById('responder-native-path');
        if (nativePath) nativePath.value = '';
        responderInput.required = true;
        requestFormSubmit(responderInput.form);
    });

    document.querySelectorAll('[data-manual-download-url]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            handleManualDownload(link.dataset.manualDownloadUrl, link.dataset.manualDownloadFilename || 'download.paracci');
        });
    });

    document.getElementById('checklist-toggle')?.addEventListener('click', () => window.toggleChecklist?.());
    document.getElementById('dismiss-y-warning')?.addEventListener('click', (e) => {
        window.dismissYWarning?.(e.currentTarget.dataset.sessionId || window.PARACCI_CONFIG?.sid || '');
    });
    document.getElementById('session-drop-zone')?.addEventListener('click', () => {
        document.getElementById('paracci_file')?.click();
    });
    document.getElementById('exit-modal-cancel')?.addEventListener('click', () => window.cancelClose?.());
    document.getElementById('exit-modal-confirm')?.addEventListener('click', () => window.confirmClose?.());
}

function updateAttachmentBadge() {
    const attInput = document.getElementById('attachments');
    const badge = document.getElementById('attachment-count-badge');
    const countVal = document.getElementById('att-count-val');
    if (!badge || !countVal) return;
    const uploadedCount = attInput?.files?.length || 0;
    const stagedCount = window.PARACCI_STAGED_ATTACHMENTS?.length || 0;
    const totalCount = uploadedCount + stagedCount;
    if (totalCount) {
        badge.style.display = 'block';
        countVal.textContent = totalCount;
    } else {
        badge.style.display = 'none';
    }
}

function setupForms() {
    // SEAL FORM
    document.getElementById('seal-form')?.addEventListener('submit', async function (e) {
        e.preventDefault();
        const btn = document.getElementById('seal-submit');
        const origText = btn.textContent;
        btn.disabled = true;
        btn.textContent = window.PARACCI_CONFIG?.armor_text || 'Processing...';
        if (window.showQuantumArmor) window.showQuantumArmor();

        try {
            const response = await fetch(this.action, { method: 'POST', body: new FormData(this) });
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
                    const b64 = reader.result.split(',')[1];
                    const savedPath = await window.pywebview.api.save_file_silent(b64, filename);
                    if (savedPath) {
                        if (window.showDownloadNotification) window.showDownloadNotification(filename, savedPath);
                        this.reset();
                        if (window.clearStagedAttachments) window.clearStagedAttachments();
                        document.getElementById('allow_download').checked = false;
                        updateAttachmentBadge();
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
            if (window.hideQuantumArmor) window.hideQuantumArmor();
        }
    });

    // OPEN MESSAGE FORM
    document.getElementById('open-message-form')?.addEventListener('submit', async function (e) {
        e.preventDefault();
        const btn = document.getElementById('btn-open-msg');
        const origText = btn.textContent;
        btn.disabled = true;
        btn.textContent = window.PARACCI_CONFIG?.armor_text || 'Processing...';
        if (window.showQuantumArmor) window.showQuantumArmor();

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
            const nativePath = document.getElementById('open-native-path');
            if (nativePath) nativePath.value = '';
            const fileInput = document.getElementById('paracci_file');
            if (fileInput) fileInput.required = true;
            document.getElementById('message-view-container').scrollIntoView({ behavior: 'smooth' });

        } catch (err) {
            console.error('[Paracci] Open error:', err);
            appendAlert(errorContainer, 'error', '', window.PARACCI_I18N?.msg_not_processed || 'Message could not be processed.');
        } finally {
            btn.disabled = false;
            btn.textContent = origText;
            if (window.hideQuantumArmor) window.hideQuantumArmor();
        }
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

    currentMsgRawText = data.text;
    
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
        const rawHtml = marked.parse(data.text);
        document.getElementById('rendered-message').innerHTML = DOMPurify.sanitize(rawHtml);
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

                const previewUrl = attachmentUrl(att, 'preview_url', '/preview');
                const previewBtn = document.createElement('button');
                previewBtn.type = 'button';
                previewBtn.className = 'btn-attachment';
                previewBtn.textContent = window.PARACCI_I18N?.preview_label || 'Preview';
                previewBtn.disabled = !previewUrl;
                previewBtn.addEventListener('click', () => handleAttachmentPreview(previewUrl));
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

async function handleSecureCopy() {
    if (!currentMsgRawText || !window._currentMsgCanCopy) return;
    
    let success = false;
    if (window.pywebview?.api?.copy_and_clear) {
        success = await window.pywebview.api.copy_and_clear(currentMsgRawText, 30);
    } else {
        try {
            await navigator.clipboard.writeText(currentMsgRawText);
            success = true;
        } catch (err) {
            console.error('[Paracci] Clipboard write error:', err);
            success = false;
        }
    }

    if (!success) {
        showNotification(window.PARACCI_I18N?.clipboard_failed_locked || "Clipboard access failed. It might be locked by another application.", "error");
        return;
    }

    const btn = document.getElementById('btn-copy-msg');
    if (!btn) return;
    let timeLeft = 30; btn.disabled = true;
    if (copyTimer) clearInterval(copyTimer);
    copyTimer = setInterval(() => {
        timeLeft--; 
        const pattern = window.PARACCI_I18N?.clearing_clipboard || "Clearing clipboard ({s}s)";
        btn.textContent = pattern.replace("{s}", timeLeft);
        if (timeLeft <= 0) {
            clearInterval(copyTimer);
            btn.textContent = window.PARACCI_I18N?.copy_protection_btn || "Copy (30s protection)"; btn.disabled = false;
            showNotification(window.PARACCI_I18N?.clipboard_cleared || "Clipboard cleared.");
        }
    }, 1000);
    showNotification(window.PARACCI_I18N?.text_copied_notify || "Text copied. Clipboard will clear in 30 seconds.");
}

async function handleManualDownload(url, filename) {
    try {
        if (window.showQuantumArmor) window.showQuantumArmor();
        const response = await fetch(url);
        if (!response.ok) throw new Error(window.PARACCI_I18N?.download_failed || 'Download failed');
        const blob = await response.blob();

        const api = window.pywebview?.api;
        if (api) {
            const reader = new FileReader();
            reader.onloadend = async () => {
                const b64 = reader.result.split(',')[1];
                let savedPath = null;
                
                // Prefer silent download for .paracci files if supported
                if (filename.endsWith('.paracci') && api.save_file_silent) {
                    savedPath = await api.save_file_silent(b64, filename);
                    if (savedPath && window.showDownloadNotification) {
                        window.showDownloadNotification(filename, savedPath);
                    }
                } else if (api.save_file) {
                    savedPath = await api.save_file(b64, filename);
                }
                
                if (window.hideQuantumArmor) window.hideQuantumArmor();
            };
            reader.readAsDataURL(blob);
        } else {
            // Browser Fallback (Legacy/Dev)
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = filename;
            link.click();
            if (window.hideQuantumArmor) window.hideQuantumArmor();
        }
    } catch (err) {
        console.error('Download error:', err);
        if (window.hideQuantumShield) window.hideQuantumShield();
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


// Global exposure
window.handleManualDownload = handleManualDownload;
window.handleSecureCopy = handleSecureCopy;
window.handleAttachmentDownload = handleAttachmentDownload;
window.triggerAutoDownload = triggerAutoDownload;
window.updateAttachmentBadge = updateAttachmentBadge;
window.toggleQuietMode = (v) => { quietMode = v; localStorage.setItem('paracci_quiet_mode', v); };
window.handleCloseClick = () => { if (quietMode) closeMessage(); else document.getElementById('exit-modal-overlay')?.classList.add('active'); };
window.cancelClose = () => document.getElementById('exit-modal-overlay')?.classList.remove('active');
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

window.toggleChecklist = () => {
    const card = document.querySelector('.collapsible-card');
    if (card) {
        card.classList.toggle('active');
    }
};

window.handleAttachmentPreview = async (target) => {
    const url = normalizeAttachmentTarget(target, false);
    if (!url) return;
    
    let api = window.pywebview?.api;
    let attempts = 0;
    while (!api?.open_preview && attempts < 10) {
        await new Promise(r => setTimeout(r, 100));
        api = window.pywebview?.api;
        attempts++;
    }

    if (api?.open_preview) {
        api.open_preview(url);
    } else {
        console.warn('pywebview API not found, falling back to window.open');
        window.open(url, '_blank', 'width=1000,height=800');
    }
};

function closeMessage() {
    const container = document.getElementById('message-view-container');
    if (container) container.style.display = 'none';
    isMessageOpen = false; currentMsgRawText = "";
    if (window.pywebview?.api?.copy_and_clear) window.pywebview.api.copy_and_clear("", 0);
    else navigator.clipboard.writeText('');
}
