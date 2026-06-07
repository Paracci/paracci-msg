/**
 * Paracci - Setup and import logic.
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

window.updateNativeUI = function (fileRef) {
    const fileInput = document.getElementById('fileInput');
    const nativeInput = document.getElementById('import-native-file-id');
    const dropArea = document.getElementById('file-drop-area');
    const dropLabel = document.getElementById('drop-label');
    const selectedText = dropArea?.dataset.selectedText || window.PARACCI_I18N?.file_selected || 'File Selected';
    const ref = typeof fileRef === 'object' && fileRef !== null
        ? fileRef
        : { id: '', filename: String(fileRef || '').split(/[\\/]/).pop() };
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

function initSetup() {
    const processingText = window.PARACCI_I18N?.processing || 'Processing...';
    const setupForm = document.getElementById('setupForm');
    const importForm = document.getElementById('importForm');
    setupCarrierImport(importForm);

    setupForm?.addEventListener('submit', () => {
        const btn = document.getElementById('submitBtn');
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<span class="spinner"></span> ${escapeHTML(processingText)}`;
        }
    });

    importForm?.addEventListener('submit', () => {
        const btn = document.getElementById('importBtn');
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<span class="spinner"></span> ${escapeHTML(processingText)}`;
        }
    });

    const fileInput = document.getElementById('fileInput');
    const dropArea = document.getElementById('file-drop-area');
    const dropLabel = document.getElementById('drop-label');
    const nativeInput = document.getElementById('import-native-file-id');

    if (fileInput && dropArea) {
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length === 0) return;
            if (nativeInput) nativeInput.value = '';
            fileInput.required = true;
            const selectedText = dropArea.dataset.selectedText || window.PARACCI_I18N?.file_selected || 'File Selected';
            dropArea.classList.add('active');
            if (dropLabel) {
                dropLabel.innerHTML = `<span class="text-accent">${escapeHTML(selectedText)}</span><br><small>${escapeHTML(fileInput.files[0].name)}</small>`;
            }
        });

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropArea.addEventListener(eventName, event => event.preventDefault(), false);
        });
        dropArea.addEventListener('dragover', () => dropArea.classList.add('highlight'), false);
        dropArea.addEventListener('dragleave', () => dropArea.classList.remove('highlight'), false);
        dropArea.addEventListener('drop', event => {
            dropArea.classList.remove('highlight');
            fileInput.files = event.dataTransfer.files;
            fileInput.dispatchEvent(new Event('change', { bubbles: true }));
        }, false);

        if (nativeInput?.value) {
            window.updateNativeUI({ id: nativeInput.value, filename: nativeInput.dataset.filename || '' });
        }
    }

    document.querySelectorAll('.custom-color-section').forEach(section => {
        const nativePicker = section.querySelector('.native-color-picker');
        const customHex = section.querySelector('.custom-color-input');
        const group = section.closest('.color-picker-group');
        const radios = group ? group.querySelectorAll('input[type="radio"]') : [];
        if (!nativePicker || !customHex) return;

        ['input', 'change'].forEach(eventName => {
            nativePicker.addEventListener(eventName, () => {
                customHex.value = nativePicker.value.replace('#', '');
                radios.forEach(radio => { radio.checked = false; });
            });
        });
        customHex.addEventListener('input', event => {
            let value = event.target.value.trim();
            if (!value.startsWith('#') && value.length > 0) value = '#' + value;
            if (value.length === 7 || value.length === 4) {
                nativePicker.value = value;
                radios.forEach(radio => { radio.checked = false; });
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
    });
}

function setupCarrierImport(importForm) {
    const carrierUi = window.ParacciCarrierUI;
    const button = document.getElementById('setup-carrier-import');
    const fileInput = document.getElementById('setup-carrier-png');
    const dropZone = document.querySelector('#setup-carrier-panel [data-carrier-drop-zone]');
    const errorContainer = document.getElementById('setup-carrier-error');
    if (!carrierUi || !importForm || !button || !fileInput) return;

    carrierUi.bindPngDropTarget(dropZone, fileInput, errorContainer);
    fileInput.addEventListener('change', () => {
        carrierUi.clearError(errorContainer);
        carrierUi.updateSelectedFileName(fileInput);
    });
    button.addEventListener('click', async () => {
        carrierUi.clearError(errorContainer);
        const labelInput = importForm.querySelector('[name="label"]');
        if (labelInput && !labelInput.reportValidity()) return;

        carrierUi.setBusy(button, true);
        try {
            const formData = new FormData(importForm);
            formData.delete('paracci_file');
            formData.delete('native_file_id');
            formData.set('carrier_png', carrierUi.selectedFile(fileInput));
            formData.set('carrier_kind', carrierUi.PNG_KIND);
            await carrierUi.submitImport(button.dataset.carrierUrl, formData);
        } catch {
            carrierUi.showGenericError(errorContainer);
        } finally {
            carrierUi.setBusy(button, false);
        }
    });
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initSetup);
} else {
    initSetup();
}
