import { BootstrapPage } from './bootstrap-page.mjs';

async function downloadBuffer(download) {
    const stream = await download.createReadStream();
    const chunks = [];
    for await (const chunk of stream) {
        chunks.push(Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
}

export class SessionWorkspace {
    constructor(page) {
        this.page = page;
        this.sessionId = '';

        this.createTab = page.getByRole('tab', { name: /encrypt message/i });
        this.openTab = page.getByRole('tab', { name: /open message/i });
        this.createStandardFormat = page.locator(
            '[data-session-format-action="create"][data-session-format="standard"]'
        );
        this.createCarrierFormat = page.locator(
            '[data-session-format-action="create"][data-session-format="carrier"]'
        );
        this.openStandardFormat = page.locator(
            '[data-session-format-action="open"][data-session-format="standard"]'
        );
        this.openCarrierFormat = page.locator(
            '[data-session-format-action="open"][data-session-format="carrier"]'
        );
        this.workspace = page.locator('#session-unified-workspace');
        this.createPanel = page.locator('#session-create-panel');
        this.openPanel = page.locator('#session-open-panel');
        this.createFormatSwitch = this.createPanel.locator('.session-format-switch');
        this.openFormatSwitch = this.openPanel.locator('.session-format-switch');
        this.pendingComposer = page.locator('#bond-pending-composer');
        this.messageComposer = page.locator('#message-composer');
        this.workspaceStatus = page.locator('#session-workspace-status-label');
        this.messageInput = page.getByRole('textbox', { name: /^Message\b/i });
        this.attachmentLabel = page.locator('label[for="attachments"]');
        this.attachmentInput = page.locator('#attachments');
        this.attachmentDropZone = page.locator('#attachment-drop-zone');
        this.selectedAttachmentsContainer = page.locator('#selected-attachments-container');
        this.selectedAttachmentItems = page.locator(
            '#selected-attachments-list .selected-attachment-item'
        );
        this.ttlControl = page.locator('.session-ttl-field .apple-custom-select-wrapper');
        this.ttlTrigger = this.ttlControl.locator('.apple-custom-select-trigger');
        this.allowDownload = page.getByLabel('Allow Saving / Downloading', { exact: true });
        this.createPrimaryAction = page.locator(
            '[data-session-standard-action="create"].session-primary-action'
        );
        this.createPrimarySummary = this.createPrimaryAction.locator(':scope > span');
        this.sealButton = page.getByRole('button', { name: 'Encrypt and download', exact: true });
        this.openFileInput = page.locator('#paracci_file');
        this.standardOpenDropZone = page.locator('#session-drop-zone');
        this.standardOpenFileLabel = page.locator('#file-label');
        this.openButton = page.getByRole('button', { name: 'Open and show', exact: true });
        this.carrierSealPanel = page.locator('#message-carrier-seal');
        this.carrierSealInput = this.carrierSealPanel.locator('[data-carrier-file]');
        this.carrierSealFileControl = this.carrierSealPanel.locator('.carrier-file-control');
        this.carrierSealFileTrigger = this.carrierSealPanel.locator('.carrier-file-trigger');
        this.carrierSealDropZone = this.carrierSealPanel.locator('[data-carrier-drop-zone]');
        this.carrierSealFilename = this.carrierSealPanel.locator('[data-carrier-file-name]');
        this.carrierSealButton = this.carrierSealPanel.locator('[data-carrier-submit]');
        this.carrierSealError = this.carrierSealPanel.locator('[data-carrier-error]');
        this.carrierOpenPanel = page.locator('#message-carrier-open');
        this.carrierOpenInput = this.carrierOpenPanel.locator('[data-carrier-file]');
        this.carrierOpenFileControl = this.carrierOpenPanel.locator('.carrier-file-control');
        this.carrierOpenFileTrigger = this.carrierOpenPanel.locator('.carrier-file-trigger');
        this.carrierOpenDropZone = this.carrierOpenPanel.locator('[data-carrier-drop-zone]');
        this.carrierOpenFilename = this.carrierOpenPanel.locator('[data-carrier-file-name]');
        this.carrierOpenButton = this.carrierOpenPanel.locator('[data-carrier-submit]');
        this.carrierOpenError = this.carrierOpenPanel.locator('[data-carrier-error]');
        this.errorContainer = page.locator('#dynamic-error-container');
        this.resultRegion = page.locator('#session-result-region');
        this.messageView = page.locator('#message-view-container');
        this.renderedMessage = page.locator('#rendered-message');
        this.singleUseAlert = page.locator('#single-use-alert');
        this.burnBadge = page.locator('#msg-badge-burn');
        this.ttlBadge = page.locator('#msg-badge-ttl');
        this.ttlTimeLeft = page.locator('#msg-time-left');
        this.allowDownloadAlert = page.locator('#allow-download-alert');
        this.noDownloadAlert = page.locator('#no-download-alert');
        this.attachmentsContainer = page.locator('#attachments-container');
        this.openedAttachmentItems = page.locator('#attachments-list-items .attachment-item');
    }

    async bootstrapAndOpenSession(entrypoint, passphrase) {
        const bootstrap = new BootstrapPage(this.page);
        await bootstrap.open(entrypoint);
        await bootstrap.unlock(passphrase);

        const sessionCard = this.page.locator('.session-card').filter({
            hasText: 'Automated Test Channel',
        }).first();
        await Promise.all([
            this.page.waitForURL(url => /^\/session\/[0-9a-f]{32}$/.test(new URL(url).pathname)),
            sessionCard.locator('.session-card-overlay').click(),
        ]);

        const match = new URL(this.page.url()).pathname.match(/^\/session\/([0-9a-f]{32})$/);
        if (!match) {
            throw new Error('Provisioned E2E session URL was not recognized.');
        }
        this.sessionId = match[1];
    }

    async selectCreate() {
        await this.createTab.click();
    }

    async selectOpen() {
        await this.openTab.click();
    }

    async selectCreateFormat(format) {
        await this.selectCreate();
        await (format === 'carrier' ? this.createCarrierFormat : this.createStandardFormat).click();
    }

    async selectOpenFormat(format) {
        await this.selectOpen();
        await (format === 'carrier' ? this.openCarrierFormat : this.openStandardFormat).click();
    }

    async prepareMessage({ text, attachment, attachments, ttlSeconds, allowDownload }) {
        await this.selectCreate();
        await this.messageInput.fill(text);
        await this.stageAttachments(attachments ?? (attachment ? [attachment] : []));
        await this.ttlTrigger.click();
        await this.ttlControl.locator(
            `.apple-custom-option[data-value="${String(ttlSeconds)}"]`
        ).click();
        if (allowDownload) {
            await this.allowDownload.check();
        } else {
            await this.allowDownload.uncheck();
        }
    }

    async stageAttachments(attachments) {
        await this.attachmentInput.setInputFiles(attachments);
    }

    selectedAttachmentRow(filename) {
        return this.selectedAttachmentItems.filter({ hasText: filename });
    }

    async removeSelectedAttachment(filename) {
        await this.selectedAttachmentRow(filename)
            .getByRole('button', { name: 'Remove file', exact: true })
            .click();
    }

    async selectedAttachmentNames() {
        return this.attachmentInput.evaluate(input => (
            Array.from(input.files || [], file => file.name)
        ));
    }

    async sealStandardMessage({ text, attachment, attachments, ttlSeconds, allowDownload }) {
        await this.prepareMessage({
            text,
            attachment,
            attachments,
            ttlSeconds,
            allowDownload,
        });
        return this.sealPreparedStandardMessage();
    }

    async sealPreparedStandardMessage() {
        await this.createStandardFormat.click();

        const downloadPromise = this.page.waitForEvent('download');
        await this.sealButton.click();
        const download = await downloadPromise;
        const filename = download.suggestedFilename();
        try {
            return {
                filename,
                buffer: await downloadBuffer(download),
            };
        } finally {
            await download.delete().catch(() => {});
        }
    }

    async sealCarrierMessage({ text, attachment, ttlSeconds, allowDownload, cover }) {
        await this.prepareMessage({ text, attachment, ttlSeconds, allowDownload });
        await this.createCarrierFormat.click();
        await this.carrierSealInput.setInputFiles(cover);

        const responsePromise = this.waitForCarrierResponse('seal');
        const downloadPromise = this.page.waitForEvent('download');
        await this.carrierSealButton.click();
        const response = await responsePromise;
        const download = await downloadPromise;
        const filename = download.suggestedFilename();
        try {
            return {
                status: response.status(),
                filename,
                buffer: await downloadBuffer(download),
            };
        } finally {
            await download.delete().catch(() => {});
        }
    }

    async submitCarrierMessage({ text, attachment, ttlSeconds, allowDownload, cover }) {
        await this.prepareMessage({ text, attachment, ttlSeconds, allowDownload });
        await this.createCarrierFormat.click();
        await this.carrierSealInput.setInputFiles(cover);

        const responsePromise = this.waitForCarrierResponse('seal');
        await this.carrierSealButton.click();
        const response = await responsePromise;
        await this.waitForCarrierIdle('#message-carrier-seal');
        return response.status();
    }

    async openStandardFile(file) {
        await this.selectOpenFormat('standard');
        await this.openFileInput.setInputFiles(file);
        return this.openSelectedStandard();
    }

    async openSelectedStandard() {
        const pathname = `/session/${this.sessionId}/open`;
        const responsePromise = this.page.waitForResponse(response => {
            const request = response.request();
            const url = new URL(response.url());
            return (
                request.method() === 'POST'
                && url.pathname === pathname
                && url.search === '?ajax=1'
            );
        });
        await this.openButton.click();
        const response = await responsePromise;
        return response.status();
    }

    async openCarrierFile(file) {
        await this.selectOpenFormat('carrier');
        await this.carrierOpenInput.setInputFiles(file);
        return this.openSelectedCarrier();
    }

    async openSelectedCarrier() {
        const responsePromise = this.waitForCarrierResponse('open');
        await this.carrierOpenButton.click();
        const response = await responsePromise;
        await this.waitForCarrierIdle('#message-carrier-open');
        return response.status();
    }

    async dropOnStandardOpen(file) {
        await this.selectOpenFormat('standard');
        await this.dropFile(this.standardOpenDropZone, file);
    }

    async dropOnCarrierOpen(file) {
        await this.selectOpenFormat('carrier');
        await this.dropFile(this.carrierOpenDropZone, file);
    }

    async dropOnAttachmentZone(files) {
        await this.dropFile(this.attachmentDropZone, files);
    }

    async dropFile(dropZone, files) {
        const sourceId = `paracci-e2e-drop-source-${Date.now()}`;
        await this.page.evaluate(id => {
            const input = document.createElement('input');
            input.id = id;
            input.type = 'file';
            input.multiple = true;
            input.hidden = true;
            document.body.appendChild(input);
        }, sourceId);
        const source = this.page.locator(`#${sourceId}`);
        try {
            await source.setInputFiles(files);
            await dropZone.evaluate((element, id) => {
                const input = document.getElementById(id);
                const transfer = new DataTransfer();
                for (const selected of input?.files || []) {
                    transfer.items.add(selected);
                }
                for (const type of ['dragenter', 'dragover', 'drop']) {
                    element.dispatchEvent(new DragEvent(type, {
                        bubbles: true,
                        cancelable: true,
                        dataTransfer: transfer,
                    }));
                }
            }, sourceId);
        } finally {
            await source.evaluate(element => element.remove()).catch(() => {});
        }
    }

    waitForCarrierResponse(action) {
        const pathname = `/session/${this.sessionId}/carrier/${action}`;
        return this.page.waitForResponse(response => {
            const request = response.request();
            const url = new URL(response.url());
            return (
                request.method() === 'POST'
                && url.pathname === pathname
                && url.search === ''
            );
        });
    }

    async waitForCarrierIdle(panelSelector) {
        await this.page.waitForFunction(selector => {
            const button = document.querySelector(`${selector} [data-carrier-submit]`);
            return Boolean(button && !button.disabled);
        }, panelSelector);
    }
}
