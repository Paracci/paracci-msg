/**
 * Paracci - Setup & Import Logic
 */

function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[char]));
}

window.updateNativeUI = function(fileRef) {
    const fileInput = document.getElementById('fileInput');
    const nativeInput = document.getElementById('import-native-file-id');
    const dropArea = document.getElementById('file-drop-area');
    const dropLabel = document.getElementById('drop-label');
    const selectedText = dropArea?.dataset.selectedText || window.PARACCI_I18N?.file_selected || 'File Selected';
    const ref = typeof fileRef === 'object' && fileRef !== null
        ? fileRef
        : { id: '', filename: String(fileRef || '').split(/[\\\/]/).pop() };
    const name = ref.filename || nativeInput?.dataset.filename || '';

    if (nativeInput) nativeInput.value = ref.id || nativeInput.value || '';
    if (fileInput) {
        fileInput.value = '';
        fileInput.required = false;
    }
    if (dropArea) dropArea.classList.add('active');
    if (dropLabel) {
        dropLabel.innerHTML = `<span class="text-accent">${escapeHTML(selectedText)}</span><br><small>${escapeHTML(name)}</small>`;
    }
};

const initSetup = () => {
    const setupForm = document.getElementById('setupForm');
    const importForm = document.getElementById('importForm');
    const armorText = setupForm?.dataset.armorText || importForm?.dataset.armorText || window.PARACCI_I18N?.argon_work_active || 'Maximum Argon2id Active...';

    if (setupForm) {
        setupForm.addEventListener('submit', () => {
            const btn = document.getElementById('submitBtn');
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = `<span class="spinner"></span> ${escapeHTML(armorText)}`;
            }
            if (window.showArgonWorkOverlay) {
                const selectedRadio = setupForm.querySelector('input[name="security_profile"]:checked');
                const profile = selectedRadio ? selectedRadio.value : 'standard';
                let params = profile;
                if (profile === 'custom') {
                    params = {
                        t: parseInt(document.getElementById('argon_t')?.value || '1', 10),
                        m: parseInt(document.getElementById('argon_m')?.value || '64', 10) * 1024, // in KiB
                        p: parseInt(document.getElementById('argon_p')?.value || '1', 10)
                    };
                }
                window.showArgonWorkOverlay('init', params);
            }
        });
    }

    if (importForm) {
        importForm.addEventListener('submit', () => {
            const btn = document.getElementById('importBtn');
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = `<span class="spinner"></span> ${escapeHTML(armorText)}`;
            }
            if (window.showArgonWorkOverlay) {
                window.showArgonWorkOverlay('accept', window._importedSecurityParams || null);
            }
        });
    }

    window.updateSecurityParams = (t, m, p) => {
        toggleCustomSecurity(false);
        const tIn = document.getElementById('argon_t');
        const mIn = document.getElementById('argon_m');
        const pIn = document.getElementById('argon_p');
        if (tIn) tIn.value = t;
        if (mIn) mIn.value = m;
        if (pIn) pIn.value = p;
        if (window.runBenchmark) window.runBenchmark();
    };

    window.runBenchmark = () => {
        const t = parseInt(document.getElementById('argon_t')?.value || 1);
        const m = parseInt(document.getElementById('argon_m')?.value || 64);
        const p = parseInt(document.getElementById('argon_p')?.value || 1);
        let estSeconds = (t * m) / 640;
        estSeconds = estSeconds / Math.max(1, Math.sqrt(p));

        const estimatedSecsEl = document.getElementById('estimated-seconds');
        if (estimatedSecsEl) {
            estimatedSecsEl.textContent = estSeconds < 0.1 ? '<0.1' : estSeconds.toFixed(1);
        }
    };

    window.toggleCustomSecurity = (show) => {
        const section = document.getElementById('custom-security-section');
        if (!section) return;
        if (show) {
            section.classList.remove('d-none');
            section.classList.add('animate-slide-up');
        } else {
            section.classList.add('d-none');
            section.classList.remove('animate-slide-up');
        }
    };

    document.querySelectorAll('[data-security-t][data-security-m][data-security-p]').forEach(input => {
        input.addEventListener('change', () => {
            if (!input.checked) return;
            window.updateSecurityParams(
                parseInt(input.dataset.securityT || '1', 10),
                parseInt(input.dataset.securityM || '64', 10),
                parseInt(input.dataset.securityP || '1', 10)
            );
        });
    });

    document.querySelectorAll('[data-custom-security="true"]').forEach(input => {
        input.addEventListener('change', () => {
            if (input.checked) window.toggleCustomSecurity(true);
        });
    });

    ['argon_t', 'argon_m', 'argon_p'].forEach(id => {
        document.getElementById(id)?.addEventListener('input', () => window.runBenchmark?.());
    });

    const fileInput = document.getElementById('fileInput');
    const dropArea = document.getElementById('file-drop-area');
    const dropLabel = document.getElementById('drop-label');
    const nativeInput = document.getElementById('import-native-file-id');

    if (fileInput && dropArea) {
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                if (nativeInput) nativeInput.value = '';
                fileInput.required = true;
                const selectedText = dropArea.dataset.selectedText || window.PARACCI_I18N?.file_selected || 'File Selected';
                dropArea.classList.add('active');
                if (dropLabel) {
                    dropLabel.innerHTML = `<span class="text-accent">${escapeHTML(selectedText)}</span><br><small>${escapeHTML(fileInput.files[0].name)}</small>`;
                }

                // Parse file to get security parameters
                const file = fileInput.files[0];
                const reader = new FileReader();
                reader.onload = function(e) {
                    try {
                        const text = e.target.result;
                        const jsonStart = text.indexOf('{');
                        if (jsonStart !== -1) {
                            const jsonStr = text.substring(jsonStart);
                            const payload = JSON.parse(jsonStr);
                            if (payload && payload.evo_config) {
                                const evo = payload.evo_config;
                                if (evo.length >= 36) {
                                    const t = parseInt(evo.substring(16, 20), 16);
                                    const m = parseInt(evo.substring(20, 28), 16); // in KiB
                                    const p = parseInt(evo.substring(28, 36), 16);
                                    window._importedSecurityParams = { t, m, p };
                                }
                            }
                        }
                    } catch (err) {
                        console.error("Failed to parse security parameters from file:", err);
                    }
                };
                reader.readAsText(file);
            }
        });

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropArea.addEventListener(eventName, (e) => {
                e.preventDefault();
            }, false);
        });

        dropArea.addEventListener('dragover', () => dropArea.classList.add('highlight'), false);
        dropArea.addEventListener('dragleave', () => dropArea.classList.remove('highlight'), false);
        dropArea.addEventListener('drop', (e) => {
            dropArea.classList.remove('highlight');
            const files = e.dataTransfer.files;
            fileInput.files = files;
            fileInput.dispatchEvent(new Event('change', { bubbles: true }));
        }, false);

        if (nativeInput?.value) {
            window.updateNativeUI({ id: nativeInput.value, filename: nativeInput.dataset.filename || '' });
        }
    }

    // Phase 2 – Color Picker Logic (Shared)
    // JS handles data-sync between native picker, hex input, and radio buttons.
    // CSS :has(input[type="radio"]:checked) handles active state visuals without JS queries.
    document.querySelectorAll('.custom-color-section').forEach(section => {
        const nativePicker = section.querySelector('.native-color-picker');
        const customHex = section.querySelector('.custom-color-input');
        const group = section.closest('.color-picker-group');
        const radios = group ? group.querySelectorAll('input[type="radio"]') : [];

        if (nativePicker && customHex) {
            const syncFromNative = () => {
                const color = nativePicker.value;
                customHex.value = color.replace('#', '');
            };

            ['input', 'change'].forEach(evt => {
                nativePicker.addEventListener(evt, () => {
                    syncFromNative();
                    radios.forEach(r => r.checked = false);
                });
            });

            customHex.addEventListener('input', (e) => {
                let val = e.target.value.trim();
                if (!val.startsWith('#') && val.length > 0) val = '#' + val;
                if (val.length === 7 || val.length === 4) {
                    nativePicker.value = val;
                    radios.forEach(r => r.checked = false);
                }
            });

            radios.forEach(radio => {
                radio.addEventListener('change', () => {
                    if (radio.checked) {
                        customHex.value = radio.value.replace('#', '');
                        nativePicker.value = radio.value;
                    }
                });
            });
        }
    });
};

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initSetup);
} else {
    initSetup();
}

window.showBenchmarkModal = async function() {
    // Phase 2: Use native <dialog> element declared in setup.html instead of
    // building a div overlay from scratch. Benefits: focus trapping, aria-modal,
    // Escape key dismissal, and ::backdrop pseudo-element — all for free.
    const dialog = document.getElementById('hw-report-dialog');
    if (!dialog) {
        alert(window.PARACCI_I18N?.hw_report_error || 'Dialog element not found');
        return;
    }

    try {
        const response = await fetch('/api/benchmark-report');
        const data = await response.json();
        if (!data.success) {
            alert((window.PARACCI_I18N?.error || 'Error') + ': ' + data.message);
            return;
        }

        // Populate dialog content
        const titleEl   = document.getElementById('hw-dialog-title-text');
        const bodyEl    = document.getElementById('hw-dialog-body');
        const closeLabel = document.getElementById('hw-dialog-close-label');

        if (titleEl)    titleEl.textContent    = window.PARACCI_I18N?.hw_report_title || 'Hardware Calibration Report';
        if (bodyEl)     bodyEl.textContent     = data.report;
        if (closeLabel) closeLabel.textContent = window.PARACCI_I18N?.close || 'Close';

        // Wire close buttons
        const closeTop    = document.getElementById('hw-dialog-close-btn');
        const closeFooter = document.getElementById('hw-dialog-footer-close');
        const closeDialog = () => dialog.close();

        if (closeTop)    { closeTop.onclick    = closeDialog; }
        if (closeFooter) { closeFooter.onclick = closeDialog; }

        // Backdrop click dismissal
        dialog.onclick = (e) => { if (e.target === dialog) dialog.close(); };

        // Open as a modal — browser provides focus trap + Escape key dismissal.
        dialog.showModal();

    } catch (err) {
        alert((window.PARACCI_I18N?.hw_report_error || 'An error occurred while fetching the report') + ': ' + err);
    }
};
