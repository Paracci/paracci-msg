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

window.updateNativeUI = function(path) {
    const fileInput = document.getElementById('fileInput');
    const nativeInput = document.getElementById('import-native-path');
    const dropArea = document.getElementById('file-drop-area');
    const dropLabel = document.getElementById('drop-label');
    const selectedText = dropArea?.dataset.selectedText || window.PARACCI_I18N?.file_selected || 'File Selected';
    const name = String(path || '').split(/[\\/]/).pop() || path;

    if (nativeInput) nativeInput.value = path || '';
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
    const armorText = setupForm?.dataset.armorText || importForm?.dataset.armorText || window.PARACCI_I18N?.quantum_armor || 'Quantum Armor Active...';

    if (setupForm) {
        setupForm.addEventListener('submit', () => {
            const btn = document.getElementById('submitBtn');
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = `<span class="spinner"></span> ${escapeHTML(armorText)}`;
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
    const nativeInput = document.getElementById('import-native-path');

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
            window.updateNativeUI(nativeInput.value);
        }
    }

    // Color Picker Logic (Shared)
    document.querySelectorAll('.custom-color-section').forEach(section => {
        const nativePicker = section.querySelector('.native-color-picker');
        const customHex = section.querySelector('.custom-color-input');
        const group = section.closest('.color-picker-group');
        const radios = group ? group.querySelectorAll('input[type="radio"]') : [];

        if (nativePicker && customHex) {
            // Function to update hex from native
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

            // Add sync from radios to custom hex
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
    try {
        const response = await fetch('/api/benchmark-report');
        const data = await response.json();
        if (!data.success) {
            alert((window.PARACCI_I18N?.error || 'Error') + ': ' + data.message);
            return;
        }

        const modal = document.createElement('div');
        modal.id = 'benchmark-modal';
        modal.className = 'p-modal-overlay active';

        const content = document.createElement('div');
        content.className = 'card p-modal';
        content.style.maxWidth = '700px';

        const closeBtn = document.createElement('button');
        closeBtn.innerHTML = '&times;';
        closeBtn.className = 'p-modal-close';
        closeBtn.onclick = () => modal.remove();

        const title = document.createElement('h2');
        title.textContent = window.PARACCI_I18N?.hw_report_title || 'Hardware Calibration Report';
        title.className = 'text-accent mb-4';

        const body = document.createElement('pre');
        body.textContent = data.report;
        body.className = 'preview-text mono font-xs p-3';

        const footer = document.createElement('div');
        footer.className = 'p-modal-footer';
        const closeBtnFooter = document.createElement('button');
        closeBtnFooter.className = 'btn btn-secondary';
        closeBtnFooter.textContent = window.PARACCI_I18N?.close || 'Close';
        closeBtnFooter.onclick = () => modal.remove();
        footer.appendChild(closeBtnFooter);

        content.appendChild(closeBtn);
        content.appendChild(title);
        content.appendChild(body);
        content.appendChild(footer);
        modal.appendChild(content);
        document.body.appendChild(modal);
        modal.onclick = (e) => {
            if (e.target === modal) modal.remove();
        };
    } catch (err) {
        alert((window.PARACCI_I18N?.hw_report_error || 'An error occurred while fetching the report') + ': ' + err);
    }
};
