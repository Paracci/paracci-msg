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
        this.pendingComposer = page.locator('#bond-pending-composer');
        this.messageComposer = page.locator('#message-composer');
        this.workspaceStatus = page.locator('#session-workspace-status-label');
        this.messageInput = page.getByRole('textbox', { name: /^Message\b/i });
        this.attachmentInput = page.locator('#attachments');
        this.ttlControl = page.locator('.session-ttl-field .apple-custom-select-wrapper');
        this.ttlTrigger = this.ttlControl.locator('.apple-custom-select-trigger');
        this.allowDownload = page.getByLabel('Allow Saving / Downloading', { exact: true });
        this.sealButton = page.getByRole('button', { name: 'Encrypt and download', exact: true });
        this.openFileInput = page.locator('#paracci_file');
        this.openButton = page.getByRole('button', { name: 'Open and show', exact: true });
        this.errorContainer = page.locator('#dynamic-error-container');
        this.messageView = page.locator('#message-view-container');
        this.renderedMessage = page.locator('#rendered-message');
        this.singleUseAlert = page.locator('#single-use-alert');
        this.burnBadge = page.locator('#msg-badge-burn');
        this.ttlBadge = page.locator('#msg-badge-ttl');
        this.ttlTimeLeft = page.locator('#msg-time-left');
        this.allowDownloadAlert = page.locator('#allow-download-alert');
        this.noDownloadAlert = page.locator('#no-download-alert');
        this.attachmentsContainer = page.locator('#attachments-container');
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

    async sealStandardMessage({ text, attachment, ttlSeconds, allowDownload }) {
        await this.selectCreate();
        await this.messageInput.fill(text);
        if (attachment) {
            await this.attachmentInput.setInputFiles(attachment);
        }
        await this.ttlTrigger.click();
        await this.ttlControl.locator(
            `.apple-custom-option[data-value="${String(ttlSeconds)}"]`
        ).click();
        if (allowDownload) {
            await this.allowDownload.check();
        } else {
            await this.allowDownload.uncheck();
        }

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

    async openStandardFile(file) {
        await this.selectOpen();
        await this.openFileInput.setInputFiles(file);

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
}
