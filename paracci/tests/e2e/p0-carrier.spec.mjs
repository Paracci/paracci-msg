import fs from 'node:fs/promises';

import { SessionWorkspace } from './session-workspace.mjs';
import { expect, test } from './fixtures.mjs';

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const MESSAGE_TEXT = 'Phase 3 PNG carrier round trip message.';
const ATTACHMENT_NAME = 'phase3-carrier-attachment.txt';
const ATTACHMENT_BYTES = Buffer.from('Synthetic Phase 3 carrier attachment.\n', 'utf8');
const WINDOWS_USER_HOME_PATTERN = new RegExp(['C:', 'Users', ''].join('\\\\'), 'i');

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

async function coverFile(profileSet, size) {
    return {
        name: size === 'large' ? 'phase3-large-cover.png' : 'phase3-tiny-cover.png',
        mimeType: 'image/png',
        buffer: await fs.readFile(profileSet.covers[size]),
    };
}

function carrierFile(download) {
    return {
        name: download.filename,
        mimeType: 'image/png',
        buffer: download.buffer,
    };
}

function expectPngDownload(download) {
    expect(download.status).toBe(200);
    expect(download.filename).toMatch(/-carrier\.png$/);
    expect(download.buffer.byteLength).toBeGreaterThan(PNG_SIGNATURE.byteLength);
    expect(download.buffer.subarray(0, PNG_SIGNATURE.byteLength)).toEqual(PNG_SIGNATURE);
}

async function withExpectedHttp422ResourceLog(page, action) {
    let active = true;
    const consoleListener = message => {
        // Chromium duplicates a non-2xx fetch as a URL-less resource console entry.
        if (
            active
            && message.type() === 'error'
            && /^Failed to load resource: the server responded with a status of 422\b/.test(
                message.text()
            )
        ) {
            message.type = () => 'debug';
            message.text = () => '[ParacciE2EExpectedHttpFailure] scoped 422 capacity response';
        }
    };

    page.prependListener('console', consoleListener);
    try {
        return await action();
    } finally {
        active = false;
        page.off('console', consoleListener);
    }
}

function assertNoSensitiveBodyDetails(bodyText, sessionPair) {
    for (const pattern of [
        /CarrierCapacityError/i,
        /CarrierRouteError/i,
        /EnvelopeError/i,
        /Traceback \(most recent call last\)/i,
        /\bDATA_DIR\b/i,
        /\bX-Paracci-Token\b/i,
        /\bX-CSRF-Token\b/i,
        /\bparacci-e2e-[^\s]+/i,
        WINDOWS_USER_HOME_PATTERN,
        /\/(?:tmp|private\/tmp)\//i,
    ]) {
        expect(bodyText).not.toMatch(pattern);
    }
    for (const sensitiveValue of [
        sessionPair.profileSet.root,
        sessionPair.profileSet.passphrase,
        sessionPair.x.runtime.entrypoint.token,
        sessionPair.y.runtime.entrypoint.token,
    ]) {
        expect(bodyText.includes(sensitiveValue)).toBe(false);
    }
}

test('@phase3 p0 PNG carrier message round trip', async ({ sessionPair }) => {
    const { xWorkspace, yWorkspace } = await bootstrapSessionPair(sessionPair);
    const largeCover = await coverFile(sessionPair.profileSet, 'large');

    await xWorkspace.selectCreateFormat('carrier');
    await expect(xWorkspace.createCarrierFormat).toHaveAttribute('aria-pressed', 'true');
    await expect(xWorkspace.createStandardFormat).toHaveAttribute('aria-pressed', 'false');

    const carrier = await xWorkspace.sealCarrierMessage({
        text: MESSAGE_TEXT,
        attachment: {
            name: ATTACHMENT_NAME,
            mimeType: 'text/plain',
            buffer: ATTACHMENT_BYTES,
        },
        ttlSeconds: 3600,
        allowDownload: true,
        cover: largeCover,
    });
    expectPngDownload(carrier);

    const yUrlBeforeOpen = sessionPair.y.page.url();
    const yNavigations = [];
    sessionPair.y.page.on('framenavigated', frame => {
        if (frame === sessionPair.y.page.mainFrame()) yNavigations.push(frame.url());
    });

    expect(await yWorkspace.openCarrierFile(carrierFile(carrier))).toBe(200);
    await expect(yWorkspace.openCarrierFormat).toHaveAttribute('aria-pressed', 'true');
    await expect(yWorkspace.messageView).toBeVisible();
    await expect(yWorkspace.renderedMessage).toHaveText(MESSAGE_TEXT);
    await expect(yWorkspace.singleUseAlert).toBeVisible();
    await expect(yWorkspace.burnBadge).toHaveText('opened - cannot reopen on this device');
    await expect(yWorkspace.ttlBadge).toBeVisible();
    await expect(yWorkspace.allowDownloadAlert).toBeVisible();
    await expect(yWorkspace.attachmentsContainer).toBeVisible();
    await expect(yWorkspace.attachmentsContainer).toContainText(ATTACHMENT_NAME);
    await expect(
        yWorkspace.attachmentsContainer.getByRole('button', { name: 'Download', exact: true })
    ).toBeVisible();

    await yWorkspace.selectCreate();
    await expect(yWorkspace.messageView).toBeVisible();
    await expect(yWorkspace.renderedMessage).toHaveText(MESSAGE_TEXT);
    await yWorkspace.selectOpen();
    await expect(yWorkspace.messageView).toBeVisible();
    await expect(yWorkspace.renderedMessage).toHaveText(MESSAGE_TEXT);
    expect(sessionPair.y.page.url()).toBe(yUrlBeforeOpen);
    expect(yNavigations).toEqual([]);

    assertNoSensitiveBodyDetails(await sessionPair.y.page.locator('body').innerText(), sessionPair);
});

test('@phase3 p0 PNG carrier insufficient capacity', async ({ sessionPair }) => {
    const { xWorkspace } = await bootstrapSessionPair(sessionPair);
    const tinyCover = await coverFile(sessionPair.profileSet, 'tiny');
    const downloads = [];
    sessionPair.x.page.on('download', download => downloads.push(download));

    const expectedCapacityScope = {
        method: 'POST',
        pathname: `/session/${xWorkspace.sessionId}/carrier/seal`,
        search: '',
        status: 422,
        step: 'insufficient PNG carrier capacity',
    };
    const capacity = await withExpectedHttp422ResourceLog(
        sessionPair.x.page,
        () => sessionPair.x.policy.expectHttpFailure(
            expectedCapacityScope,
            () => xWorkspace.submitCarrierMessage({
                text: 'phase3-capacity-payload-sentinel',
                attachment: null,
                ttlSeconds: 0,
                allowDownload: false,
                cover: tinyCover,
            })
        )
    );

    expect(capacity.matched).toBe(true);
    expect(capacity.result).toBe(422);
    await expect(xWorkspace.carrierSealError).toHaveText(
        'The selected cover PNG does not have enough pixel capacity for this message. '
        + 'Attachments need a larger high-resolution lossless PNG.'
    );
    const guidance = await xWorkspace.carrierSealError.innerText();
    expect(guidance).not.toMatch(
        /\b32\b|\b\d+\s*(?:bytes?|kb|mb|pixels?)\b|payload|phase3-tiny|sentinel|path|token|response|success|Carrier file could not/i
    );
    await sessionPair.x.page.waitForTimeout(200);
    expect(downloads).toEqual([]);
    assertNoSensitiveBodyDetails(await sessionPair.x.page.locator('body').innerText(), sessionPair);
});

test('@phase3 p0 scoped PNG carrier drag and drop', async ({ sessionPair }) => {
    const { xWorkspace, yWorkspace } = await bootstrapSessionPair(sessionPair);
    const carrier = await xWorkspace.sealCarrierMessage({
        text: 'Phase 3 scoped carrier drop message.',
        attachment: null,
        ttlSeconds: 0,
        allowDownload: false,
        cover: await coverFile(sessionPair.profileSet, 'large'),
    });
    expectPngDownload(carrier);
    const upload = carrierFile(carrier);

    const carrierOpenRequests = [];
    sessionPair.y.page.on('request', request => {
        const url = new URL(request.url());
        if (
            request.method() === 'POST'
            && url.pathname === `/session/${yWorkspace.sessionId}/carrier/open`
        ) {
            carrierOpenRequests.push(request.url());
        }
    });

    await yWorkspace.dropOnStandardOpen(upload);
    await expect(
        sessionPair.y.page.locator('body > .alert.alert-info').filter({
            hasText: 'This file cannot be dropped in the current view.',
        })
    ).toBeVisible();
    await expect(yWorkspace.openStandardFormat).toHaveAttribute('aria-pressed', 'true');
    await expect(yWorkspace.standardOpenFileLabel).toHaveText('No message file selected');
    expect(await yWorkspace.openFileInput.evaluate(input => input.files.length)).toBe(0);
    expect(await yWorkspace.carrierOpenInput.evaluate(input => input.files.length)).toBe(0);
    expect(carrierOpenRequests).toEqual([]);

    await yWorkspace.dropOnCarrierOpen(upload);
    await expect(yWorkspace.openCarrierFormat).toHaveAttribute('aria-pressed', 'true');
    await expect(yWorkspace.carrierOpenFilename).toHaveText(carrier.filename);
    expect(await yWorkspace.carrierOpenInput.evaluate(input => input.files.length)).toBe(1);
    expect(await yWorkspace.openSelectedCarrier()).toBe(200);
    await expect(yWorkspace.messageView).toBeVisible();
    await expect(yWorkspace.renderedMessage).toHaveText(
        'Phase 3 scoped carrier drop message.'
    );
    expect(carrierOpenRequests).toHaveLength(1);
    assertNoSensitiveBodyDetails(await sessionPair.y.page.locator('body').innerText(), sessionPair);
});
