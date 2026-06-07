/**
 * Explicit PNG carrier UI helpers.
 *
 * Carrier failures intentionally collapse to one localized public message.
 */
(function initCarrierUi(global) {
    'use strict';

    const PNG_KIND = 'png_lossless_v1';
    const DOWNLOAD_NAME = 'carrier.png';

    function i18n(key, fallback) {
        return global.PARACCI_I18N?.[key] || fallback;
    }

    function genericErrorText() {
        return i18n('carrier_generic_error', 'Carrier file could not be processed safely.');
    }

    function carrierError() {
        const error = new Error(genericErrorText());
        error.name = 'CarrierUIError';
        return error;
    }

    function clearError(container) {
        container?.replaceChildren();
    }

    function showGenericError(container) {
        if (!container) return;
        clearError(container);
        const alert = document.createElement('div');
        alert.className = 'alert alert-error';
        alert.textContent = genericErrorText();
        container.appendChild(alert);
    }

    function selectedFile(input) {
        const file = input?.files?.[0];
        if (!file) throw carrierError();
        return file;
    }

    function setBusy(button, busy) {
        if (!button) return;
        if (busy) {
            button.dataset.carrierOriginalText = button.textContent;
            button.disabled = true;
            button.textContent = i18n('carrier_processing', 'Processing...');
            return;
        }
        button.disabled = false;
        if (button.dataset.carrierOriginalText) {
            button.textContent = button.dataset.carrierOriginalText;
            delete button.dataset.carrierOriginalText;
        }
    }

    function isNativeSaveAvailable() {
        return typeof global.pywebview?.api?.save_file_silent === 'function';
    }

    async function postMultipart(url, formData, { nativeSave = false } = {}) {
        const headers = nativeSave ? { 'X-Paracci-Native-Save': '1' } : undefined;
        try {
            return await global.fetch(url, {
                method: 'POST',
                headers,
                body: formData
            });
        } catch {
            throw carrierError();
        }
    }

    async function submitImport(url, formData) {
        const response = await postMultipart(url, formData);
        if (!response.ok || !response.redirected || !response.url) throw carrierError();
        const navigate = global.ParacciSecurity?.navigateAuthorized;
        if (typeof navigate !== 'function') throw carrierError();
        const navigated = await navigate(response.url);
        if (!navigated) throw carrierError();
    }

    async function submitOpen(url, formData) {
        const response = await postMultipart(url, formData);
        if (!response.ok) throw carrierError();
        let data;
        try {
            data = await response.json();
        } catch {
            throw carrierError();
        }
        if (data?.success !== true) throw carrierError();
        return data;
    }

    async function submitDownload(url, formData) {
        const nativeSave = isNativeSaveAvailable();
        const response = await postMultipart(url, formData, { nativeSave });
        if (!response.ok) throw carrierError();

        if (nativeSave) {
            let grant;
            try {
                grant = await response.json();
            } catch {
                throw carrierError();
            }
            if (!grant?.native_save_token) throw carrierError();
            const loopbackToken = global.ParacciSecurity?.getLoopbackToken?.() || '';
            let savedPath;
            try {
                savedPath = await global.pywebview.api.save_file_silent(
                    grant.native_save_token,
                    loopbackToken
                );
            } catch {
                throw carrierError();
            }
            if (!savedPath) throw carrierError();
            global.showDownloadNotification?.(DOWNLOAD_NAME, null);
            return;
        }

        let blob;
        try {
            blob = await response.blob();
        } catch {
            throw carrierError();
        }
        const objectUrl = global.URL.createObjectURL(blob);
        try {
            const anchor = document.createElement('a');
            anchor.href = objectUrl;
            anchor.download = DOWNLOAD_NAME;
            document.body.appendChild(anchor);
            anchor.click();
            anchor.remove();
        } finally {
            global.URL.revokeObjectURL(objectUrl);
        }
    }

    global.ParacciCarrierUI = Object.freeze({
        PNG_KIND,
        clearError,
        selectedFile,
        setBusy,
        showGenericError,
        submitDownload,
        submitImport,
        submitOpen
    });
})(window);
