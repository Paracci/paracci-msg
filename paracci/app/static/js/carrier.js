/**
 * Explicit PNG carrier UI helpers.
 *
 * Carrier failures intentionally collapse to one localized public message.
 */
(function initCarrierUi(global) {
    'use strict';

    const PNG_KIND = 'png_lossless_v1';
    const FALLBACK_DOWNLOAD_NAME = 'image-carrier.png';
    const MAX_SAFE_FILENAME_LENGTH = 180;

    function i18n(key, fallback) {
        return global.PARACCI_I18N?.[key] || fallback;
    }

    function genericErrorText() {
        return i18n('carrier_generic_error', 'Carrier file could not be processed safely.');
    }

    function capacityErrorText() {
        return i18n(
            'carrier_capacity_error',
            'The selected PNG does not have enough room. Choose a larger lossless PNG.'
        );
    }

    function carrierError(kind = 'generic') {
        const error = new Error(kind === 'capacity' ? capacityErrorText() : genericErrorText());
        error.name = 'CarrierUIError';
        error.kind = kind;
        return error;
    }

    function clearError(container) {
        container?.replaceChildren();
    }

    function showGenericError(container) {
        showError(container, carrierError());
    }

    function showError(container, error) {
        if (!container) return;
        clearError(container);
        const alert = document.createElement('div');
        alert.className = 'alert alert-error';
        alert.textContent = error?.kind === 'capacity'
            ? capacityErrorText()
            : genericErrorText();
        container.appendChild(alert);
    }

    function selectedFile(input) {
        const file = input?.files?.[0];
        if (!file) throw carrierError();
        return file;
    }

    function updateSelectedFileName(input) {
        const container = input?.closest?.('.carrier-file-control');
        const output = container?.querySelector?.('[data-carrier-file-name]');
        if (!output) return;
        output.textContent = input.files?.[0]?.name || output.dataset.emptyLabel || '';
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
        if (!response.ok) {
            throw carrierError(response.status === 422 ? 'capacity' : 'generic');
        }

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
            global.showDownloadNotification?.(
                safePngFilename(grant.filename),
                savedPath
            );
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
            anchor.download = safePngFilename(
                response.headers?.get?.('Content-Disposition')
            );
            document.body.appendChild(anchor);
            anchor.click();
            anchor.remove();
        } finally {
            global.URL.revokeObjectURL(objectUrl);
        }
    }

    function safePngFilename(value) {
        const raw = String(value || '');
        const dispositionMatch = raw.match(
            /(?:^|;)\s*filename=(?:"([A-Za-z0-9._-]+)"|([A-Za-z0-9._-]+))\s*(?:;|$)/i
        );
        const candidate = dispositionMatch
            ? dispositionMatch[1] || dispositionMatch[2]
            : raw;
        if (
            candidate.length > 0
            && candidate.length <= MAX_SAFE_FILENAME_LENGTH
            && /^[A-Za-z0-9][A-Za-z0-9._-]*\.png$/i.test(candidate)
        ) {
            return candidate;
        }
        return FALLBACK_DOWNLOAD_NAME;
    }

    global.ParacciCarrierUI = Object.freeze({
        PNG_KIND,
        clearError,
        safePngFilename,
        selectedFile,
        setBusy,
        showError,
        showGenericError,
        submitDownload,
        submitImport,
        submitOpen,
        updateSelectedFileName
    });
})(window);
