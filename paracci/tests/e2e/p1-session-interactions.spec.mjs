import { SessionWorkspace } from './session-workspace.mjs';
import { expect, test } from './fixtures.mjs';

function syntheticTextFile(name, content) {
    return {
        name,
        mimeType: 'text/plain',
        buffer: Buffer.from(content, 'utf8'),
    };
}

function standardEnvelopeFile(envelope) {
    return {
        name: envelope.filename,
        mimeType: 'application/octet-stream',
        buffer: envelope.buffer,
    };
}

async function bootstrapSessionPair(sessionPair) {
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
    return { xWorkspace, yWorkspace };
}

function observeMessageOpenRequests(page, sessionId) {
    const requests = {
        carrier: [],
        standard: [],
    };
    page.on('request', request => {
        if (request.method() !== 'POST') return;
        const url = new URL(request.url());
        if (url.pathname === `/session/${sessionId}/open` && url.search === '?ajax=1') {
            requests.standard.push(request.url());
        }
        if (url.pathname === `/session/${sessionId}/carrier/open` && url.search === '') {
            requests.carrier.push(request.url());
        }
    });
    return requests;
}

test('@phase4 p1 attachment removal persists through standard round trip', async ({
    sessionPair,
}) => {
    const { xWorkspace, yWorkspace } = await bootstrapSessionPair(sessionPair);
    const retainedFirst = syntheticTextFile(
        'phase4b-retained-first.txt',
        'Phase 4B retained first attachment content.\n'
    );
    const removed = syntheticTextFile(
        'phase4b-removed-middle.txt',
        'PHASE4B-REMOVED-CONTENT-SENTINEL\n'
    );
    const retainedLast = syntheticTextFile(
        'phase4b-retained-last.txt',
        'Phase 4B retained last attachment content.\n'
    );

    await xWorkspace.prepareMessage({
        text: 'Phase 4B attachment editing round trip.',
        attachments: [retainedFirst, removed, retainedLast],
        ttlSeconds: 3600,
        allowDownload: true,
    });
    await expect(xWorkspace.selectedAttachmentsContainer).toBeVisible();
    await expect(xWorkspace.selectedAttachmentItems).toHaveCount(3);
    expect(await xWorkspace.selectedAttachmentNames()).toEqual([
        retainedFirst.name,
        removed.name,
        retainedLast.name,
    ]);

    await xWorkspace.removeSelectedAttachment(removed.name);
    await expect(xWorkspace.selectedAttachmentItems).toHaveCount(2);
    expect(await xWorkspace.selectedAttachmentNames()).toEqual([
        retainedFirst.name,
        retainedLast.name,
    ]);
    await expect(xWorkspace.selectedAttachmentRow(removed.name)).toHaveCount(0);

    const envelope = await xWorkspace.sealPreparedStandardMessage();
    expect(await yWorkspace.openStandardFile(standardEnvelopeFile(envelope))).toBe(200);
    await expect(yWorkspace.attachmentsContainer).toBeVisible();
    await expect(yWorkspace.openedAttachmentItems).toHaveCount(2);
    await expect(yWorkspace.openedAttachmentItems.filter({
        hasText: retainedFirst.name,
    })).toHaveCount(1);
    await expect(yWorkspace.openedAttachmentItems.filter({
        hasText: retainedLast.name,
    })).toHaveCount(1);
    await expect(yWorkspace.openedAttachmentItems.filter({
        hasText: removed.name,
    })).toHaveCount(0);
    await expect(yWorkspace.attachmentsContainer).not.toContainText(removed.name);
    await expect(sessionPair.y.page.locator('body')).not.toContainText(
        'PHASE4B-REMOVED-CONTENT-SENTINEL'
    );
});

test('@phase4 p1 saving disabled hides attachment download controls', async ({
    sessionPair,
}) => {
    const { xWorkspace, yWorkspace } = await bootstrapSessionPair(sessionPair);
    const attachment = syntheticTextFile(
        'phase4b-no-saving.txt',
        'Synthetic Phase 4B no-saving attachment.\n'
    );
    const envelope = await xWorkspace.sealStandardMessage({
        text: 'Phase 4B saving-disabled message.',
        attachment,
        ttlSeconds: 0,
        allowDownload: false,
    });

    expect(await yWorkspace.openStandardFile(standardEnvelopeFile(envelope))).toBe(200);
    await expect(yWorkspace.messageView).toHaveAttribute('data-allow-download', 'false');
    await expect(yWorkspace.noDownloadAlert).toBeVisible();
    await expect(yWorkspace.noDownloadAlert).toContainText(/viewing only|cannot be saved/i);
    await expect(yWorkspace.allowDownloadAlert).toBeHidden();
    await expect(yWorkspace.attachmentsContainer).toBeVisible();
    await expect(yWorkspace.openedAttachmentItems).toHaveCount(1);

    const attachmentRow = yWorkspace.openedAttachmentItems.filter({
        hasText: attachment.name,
    });
    await expect(attachmentRow).toHaveCount(1);
    await expect(attachmentRow).toContainText(attachment.name);
    await expect(
        attachmentRow.getByRole('button', { name: 'Preview', exact: true })
    ).toBeEnabled();
    await expect(
        attachmentRow.getByRole('button', { name: 'Download', exact: true })
    ).toHaveCount(0);
});

test('@phase4 p1 standard and attachment drops preserve global routing', async ({
    sessionPair,
}) => {
    const { xWorkspace, yWorkspace } = await bootstrapSessionPair(sessionPair);
    const envelope = await xWorkspace.sealStandardMessage({
        text: 'Phase 4B standard drop routing message.',
        attachment: null,
        ttlSeconds: 0,
        allowDownload: false,
    });
    const upload = standardEnvelopeFile(envelope);
    const openRequests = observeMessageOpenRequests(
        sessionPair.y.page,
        yWorkspace.sessionId
    );

    await yWorkspace.dropOnStandardOpen(upload);
    await expect(yWorkspace.openTab).toHaveAttribute('aria-selected', 'true');
    await expect(yWorkspace.openStandardFormat).toHaveAttribute('aria-pressed', 'true');
    await expect(yWorkspace.standardOpenFileLabel).toHaveText(upload.name);
    expect(await yWorkspace.openFileInput.evaluate(input => (
        Array.from(input.files || [], file => file.name)
    ))).toEqual([upload.name]);
    expect(await yWorkspace.carrierOpenInput.evaluate(input => input.files.length)).toBe(0);
    expect(await yWorkspace.selectedAttachmentNames()).toEqual([]);
    expect(openRequests.standard).toEqual([]);
    expect(openRequests.carrier).toEqual([]);

    expect(await yWorkspace.openSelectedStandard()).toBe(200);
    await expect(yWorkspace.renderedMessage).toHaveText(
        'Phase 4B standard drop routing message.'
    );
    expect(openRequests.standard).toHaveLength(1);
    expect(openRequests.carrier).toEqual([]);
    await expect(yWorkspace.createTab).toHaveAttribute('aria-selected', 'true');
    await expect(yWorkspace.messageComposer).toBeVisible();

    const droppedAttachments = [
        syntheticTextFile(
            'phase4b-dropped-first.txt',
            'Phase 4B first dropped attachment.\n'
        ),
        syntheticTextFile(
            'phase4b-dropped-second.txt',
            'Phase 4B second dropped attachment.\n'
        ),
    ];
    await yWorkspace.dropOnAttachmentZone(droppedAttachments);
    await expect(yWorkspace.createTab).toHaveAttribute('aria-selected', 'true');
    await expect(yWorkspace.createPanel).toBeVisible();
    await expect(yWorkspace.selectedAttachmentsContainer).toBeVisible();
    await expect(yWorkspace.selectedAttachmentItems).toHaveCount(2);
    expect(await yWorkspace.selectedAttachmentNames()).toEqual(
        droppedAttachments.map(file => file.name)
    );
    expect(await yWorkspace.openFileInput.evaluate(input => input.files.length)).toBe(0);
    expect(await yWorkspace.carrierOpenInput.evaluate(input => input.files.length)).toBe(0);
    expect(openRequests.standard).toHaveLength(1);
    expect(openRequests.carrier).toEqual([]);
});
