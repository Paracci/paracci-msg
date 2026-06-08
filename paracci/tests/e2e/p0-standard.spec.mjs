import { SessionWorkspace } from './session-workspace.mjs';
import { expect, test } from './fixtures.mjs';

const MESSAGE_TEXT = 'Phase 2 standard round trip message.';
const ATTACHMENT_NAME = 'phase2-attachment.txt';
const ATTACHMENT_BYTES = Buffer.from('Synthetic Phase 2 attachment content.\n', 'utf8');
const WINDOWS_USER_HOME_PATTERN = new RegExp(['C:', 'Users', ''].join('\\\\'), 'i');

function assertNoSensitiveBodyDetails(bodyText, sessionPair) {
    const forbiddenPatterns = [
        /AlreadyBurnedError/i,
        /EnvelopeError/i,
        /Traceback \(most recent call last\)/i,
        /\bDATA_DIR\b/i,
        /\bX-Paracci-Token\b/i,
        /\bX-CSRF-Token\b/i,
        /\bopen_upload_[0-9a-f]+\b/i,
        /\bparacci-e2e-[^\s]+/i,
        WINDOWS_USER_HOME_PATTERN,
        /\/(?:tmp|private\/tmp)\//i,
    ];
    for (const pattern of forbiddenPatterns) {
        expect(bodyText).not.toMatch(pattern);
    }

    for (const sensitiveValue of [
        sessionPair.profileSet.root,
        sessionPair.profileSet.passphrase,
        sessionPair.x.runtime.entrypoint.token,
        sessionPair.y.runtime.entrypoint.token,
    ]) {
        expect(
            bodyText.includes(sensitiveValue),
            'Rendered page must not expose E2E roots, credentials, or loopback tokens.'
        ).toBe(false);
    }
}

test('@phase2 p0 standard .paracci first-message round trip and replay rejection', async ({
    sessionPair,
}) => {
    const xWorkspace = new SessionWorkspace(sessionPair.x.page);
    const yWorkspace = new SessionWorkspace(sessionPair.y.page);

    await Promise.all([
        xWorkspace.bootstrapAndOpenSession(
            sessionPair.x.runtime.entrypoint.href,
            sessionPair.profileSet.passphrase
        ),
        yWorkspace.bootstrapAndOpenSession(
            sessionPair.y.runtime.entrypoint.href,
            sessionPair.profileSet.passphrase
        ),
    ]);
    expect(yWorkspace.sessionId).toBe(xWorkspace.sessionId);

    await yWorkspace.selectCreate();
    await expect(yWorkspace.workspaceStatus).toHaveText('Bonding pending');
    await expect(yWorkspace.pendingComposer).toBeVisible();
    await expect(yWorkspace.pendingComposer).toContainText(
        "The Initiator (X) must send the first message"
    );
    await expect(yWorkspace.messageComposer).toBeHidden();

    const envelope = await xWorkspace.sealStandardMessage({
        text: MESSAGE_TEXT,
        attachment: {
            name: ATTACHMENT_NAME,
            mimeType: 'text/plain',
            buffer: ATTACHMENT_BYTES,
        },
        ttlSeconds: 3600,
        allowDownload: true,
    });
    expect(envelope.filename).toMatch(/^msg_step_000000_[0-9a-f]{12}\.paracci$/);
    expect(envelope.buffer.byteLength).toBeGreaterThan(0);

    const upload = {
        name: envelope.filename,
        mimeType: 'application/octet-stream',
        buffer: envelope.buffer,
    };
    const yUrlBeforeOpen = sessionPair.y.page.url();
    const yNavigations = [];
    sessionPair.y.page.on('framenavigated', frame => {
        if (frame === sessionPair.y.page.mainFrame()) {
            yNavigations.push(frame.url());
        }
    });

    expect(await yWorkspace.openStandardFile(upload)).toBe(200);
    await expect(yWorkspace.messageView).toBeVisible();
    await expect(yWorkspace.renderedMessage).toHaveText(MESSAGE_TEXT);
    await expect(yWorkspace.singleUseAlert).toBeVisible();
    await expect(yWorkspace.singleUseAlert).toContainText(
        'cannot be opened again on this device'
    );
    await expect(yWorkspace.burnBadge).toHaveText('opened - cannot reopen on this device');
    await expect(yWorkspace.ttlBadge).toBeVisible();
    await expect(yWorkspace.ttlTimeLeft).not.toHaveText('');
    await expect(yWorkspace.allowDownloadAlert).toBeVisible();
    await expect(yWorkspace.allowDownloadAlert).toContainText('saving/downloading');
    await expect(yWorkspace.noDownloadAlert).toBeHidden();
    await expect(yWorkspace.attachmentsContainer).toBeVisible();
    await expect(yWorkspace.attachmentsContainer).toContainText(ATTACHMENT_NAME);
    await expect(
        yWorkspace.attachmentsContainer.getByRole('button', { name: 'Download', exact: true })
    ).toBeVisible();

    await expect(yWorkspace.pendingComposer).toHaveCount(0);
    await expect(yWorkspace.messageComposer).toBeVisible();
    await expect(yWorkspace.createTab).toHaveAttribute('aria-selected', 'true');
    expect(sessionPair.y.page.url()).toBe(yUrlBeforeOpen);
    expect(yNavigations).toEqual([]);

    await yWorkspace.selectOpen();
    await expect(yWorkspace.messageView).toBeVisible();
    await expect(yWorkspace.renderedMessage).toHaveText(MESSAGE_TEXT);
    await yWorkspace.selectCreate();
    await expect(yWorkspace.messageView).toBeVisible();
    await expect(yWorkspace.renderedMessage).toHaveText(MESSAGE_TEXT);

    const replay = await sessionPair.y.policy.expectHttpFailure(
        {
            method: 'POST',
            pathname: `/session/${yWorkspace.sessionId}/open`,
            search: '?ajax=1',
            status: 400,
            step: 'replay standard paracci open',
        },
        async () => {
            const status = await yWorkspace.openStandardFile(upload);
            await expect(yWorkspace.errorContainer).toBeVisible();
            return status;
        }
    );
    expect(replay.result).toBe(replay.matched ? 400 : 200);
    await expect(yWorkspace.errorContainer).toHaveText(
        'Error: Message could not be processed'
    );
    const replayError = await yWorkspace.errorContainer.innerText();
    expect(replayError).not.toMatch(
        /already|expired|replay|protocol|decrypt|burn|traceback|token|path|response|success/i
    );

    await expect(yWorkspace.messageView).toBeVisible();
    await expect(yWorkspace.renderedMessage).toHaveText(MESSAGE_TEXT);
    expect(sessionPair.y.page.url()).toBe(yUrlBeforeOpen);
    expect(yNavigations).toEqual([]);

    assertNoSensitiveBodyDetails(await sessionPair.y.page.locator('body').innerText(), sessionPair);
});
