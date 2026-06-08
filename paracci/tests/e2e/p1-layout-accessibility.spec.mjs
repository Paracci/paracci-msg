import { SessionWorkspace } from './session-workspace.mjs';
import { expect, test } from './fixtures.mjs';

const DESKTOP_VIEWPORTS = [
    { name: 'normal desktop', width: 1280, height: 900 },
    { name: 'compact desktop window', width: 900, height: 700 },
];
const MESSAGE_TEXT = 'Phase 4A desktop layout stability message.';
const ATTACHMENT_NAME = 'phase4a-layout-attachment.txt';
const ATTACHMENT_BYTES = Buffer.from('Synthetic Phase 4A layout attachment.\n', 'utf8');

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

async function expectNoDocumentHorizontalOverflow(page, viewportName) {
    const dimensions = await page.evaluate(() => ({
        body: document.body.scrollWidth,
        document: document.documentElement.scrollWidth,
        viewport: document.documentElement.clientWidth,
    }));
    expect(
        Math.max(dimensions.body, dimensions.document),
        `${viewportName} must not have document-level horizontal overflow`
    ).toBeLessThanOrEqual(dimensions.viewport);
}

async function expectViewportReachable(locator, label) {
    await expect(locator, `${label} must be visible`).toBeVisible();
    await locator.scrollIntoViewIfNeeded();
    const bounds = await locator.evaluate(element => {
        const rect = element.getBoundingClientRect();
        return {
            bottom: rect.bottom,
            height: rect.height,
            left: rect.left,
            right: rect.right,
            top: rect.top,
            viewportHeight: window.innerHeight,
            viewportWidth: window.innerWidth,
            width: rect.width,
        };
    });
    expect(bounds.width, `${label} must have rendered width`).toBeGreaterThan(0);
    expect(bounds.height, `${label} must have rendered height`).toBeGreaterThan(0);
    expect(bounds.left, `${label} must not extend past the left viewport edge`).toBeGreaterThanOrEqual(-1);
    expect(bounds.right, `${label} must not extend past the right viewport edge`).toBeLessThanOrEqual(
        bounds.viewportWidth + 1
    );
    expect(bounds.bottom, `${label} must be vertically reachable`).toBeGreaterThan(0);
    expect(bounds.top, `${label} must intersect the visible viewport after scrolling`).toBeLessThan(
        bounds.viewportHeight
    );
}

async function expectNoObviousOverlap(first, second, label) {
    const [firstBox, secondBox] = await Promise.all([
        first.boundingBox(),
        second.boundingBox(),
    ]);
    expect(firstBox, `${label}: first control must have a layout box`).not.toBeNull();
    expect(secondBox, `${label}: second control must have a layout box`).not.toBeNull();

    const horizontalOverlap = Math.min(
        firstBox.x + firstBox.width,
        secondBox.x + secondBox.width
    ) - Math.max(firstBox.x, secondBox.x);
    const verticalOverlap = Math.min(
        firstBox.y + firstBox.height,
        secondBox.y + secondBox.height
    ) - Math.max(firstBox.y, secondBox.y);
    expect(
        horizontalOverlap > 2 && verticalOverlap > 2,
        `${label} must not visibly overlap`
    ).toBe(false);
}

async function focusStyle(locator) {
    return locator.evaluate(element => {
        const style = getComputedStyle(element);
        return {
            backgroundColor: style.backgroundColor,
            borderBottomColor: style.borderBottomColor,
            borderLeftColor: style.borderLeftColor,
            borderRightColor: style.borderRightColor,
            borderTopColor: style.borderTopColor,
            boxShadow: style.boxShadow,
            outlineColor: style.outlineColor,
            outlineStyle: style.outlineStyle,
            outlineWidth: style.outlineWidth,
        };
    });
}

function visibleOutline(style) {
    return (
        style.outlineStyle !== 'none'
        && Number.parseFloat(style.outlineWidth) > 0
        && style.outlineColor !== 'transparent'
        && style.outlineColor !== 'rgba(0, 0, 0, 0)'
    );
}

function changedFocusDecoration(before, after) {
    return (
        (after.boxShadow !== 'none' && after.boxShadow !== before.boxShadow)
        || after.backgroundColor !== before.backgroundColor
        || after.borderTopColor !== before.borderTopColor
        || after.borderRightColor !== before.borderRightColor
        || after.borderBottomColor !== before.borderBottomColor
        || after.borderLeftColor !== before.borderLeftColor
    );
}

async function expectVisibleFocusIndicator(
    control,
    label,
    { indicator = control, unfocusedStyle } = {}
) {
    await expect(control, `${label} must receive keyboard focus`).toBeFocused();
    expect(
        await control.evaluate(element => element.matches(':focus-visible')),
        `${label} must match :focus-visible after keyboard navigation`
    ).toBe(true);
    const focusedStyle = await focusStyle(indicator);
    expect(
        visibleOutline(focusedStyle)
            || (unfocusedStyle && changedFocusDecoration(unfocusedStyle, focusedStyle)),
        `${label} must expose a visible outline, shadow, border, or background focus indicator`
    ).toBe(true);
}

test('@phase4 p1 desktop session workspace layout stability at supported desktop sizes', async ({
    sessionPair,
}) => {
    test.slow();
    const { xWorkspace, yWorkspace } = await bootstrapSessionPair(sessionPair);
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
    expect(await yWorkspace.openStandardFile({
        name: envelope.filename,
        mimeType: 'application/octet-stream',
        buffer: envelope.buffer,
    })).toBe(200);
    await expect(yWorkspace.renderedMessage).toHaveText(MESSAGE_TEXT);
    await expect(yWorkspace.attachmentsContainer).toContainText(ATTACHMENT_NAME);

    for (const viewport of DESKTOP_VIEWPORTS) {
        await Promise.all([
            sessionPair.x.page.setViewportSize(viewport),
            sessionPair.y.page.setViewportSize(viewport),
        ]);

        await xWorkspace.selectCreateFormat('standard');
        await expectNoDocumentHorizontalOverflow(sessionPair.x.page, viewport.name);
        for (const [locator, label] of [
            [xWorkspace.workspace, `${viewport.name} Create/Open workspace`],
            [xWorkspace.createPanel, `${viewport.name} Create panel`],
            [xWorkspace.messageInput, `${viewport.name} message field`],
            [xWorkspace.attachmentDropZone, `${viewport.name} attachment picker`],
            [xWorkspace.createFormatSwitch, `${viewport.name} Create format controls`],
            [xWorkspace.createPrimaryAction, `${viewport.name} Create primary action`],
            [xWorkspace.sealButton, `${viewport.name} Encrypt and download button`],
        ]) {
            await expectViewportReachable(locator, label);
        }
        await expectNoObviousOverlap(
            xWorkspace.createTab,
            xWorkspace.openTab,
            `${viewport.name} Create/Open tabs`
        );
        await expectNoObviousOverlap(
            xWorkspace.messageInput,
            xWorkspace.attachmentDropZone,
            `${viewport.name} message and attachment controls`
        );
        await expectNoObviousOverlap(
            xWorkspace.createStandardFormat,
            xWorkspace.createCarrierFormat,
            `${viewport.name} Create format controls`
        );
        await expectNoObviousOverlap(
            xWorkspace.createPrimarySummary,
            xWorkspace.sealButton,
            `${viewport.name} Create primary action content`
        );

        await xWorkspace.selectCreateFormat('carrier');
        await expectNoDocumentHorizontalOverflow(sessionPair.x.page, viewport.name);
        for (const [locator, label] of [
            [xWorkspace.carrierSealPanel, `${viewport.name} carrier Create controls`],
            [xWorkspace.carrierSealFileControl, `${viewport.name} carrier PNG picker`],
            [xWorkspace.carrierSealButton, `${viewport.name} carrier Create action`],
        ]) {
            await expectViewportReachable(locator, label);
        }
        await expectNoObviousOverlap(
            xWorkspace.carrierSealFileControl,
            xWorkspace.carrierSealButton,
            `${viewport.name} carrier Create picker and action`
        );

        await yWorkspace.selectOpenFormat('standard');
        await expectNoDocumentHorizontalOverflow(sessionPair.y.page, viewport.name);
        for (const [locator, label] of [
            [yWorkspace.workspace, `${viewport.name} receiver Create/Open workspace`],
            [yWorkspace.openPanel, `${viewport.name} Open panel`],
            [yWorkspace.openFormatSwitch, `${viewport.name} Open format controls`],
            [yWorkspace.standardOpenDropZone, `${viewport.name} standard message picker`],
            [yWorkspace.openButton, `${viewport.name} Open and show button`],
            [yWorkspace.resultRegion, `${viewport.name} open result area`],
            [yWorkspace.messageView, `${viewport.name} opened message`],
            [yWorkspace.attachmentsContainer, `${viewport.name} opened attachment list`],
        ]) {
            await expectViewportReachable(locator, label);
        }
        await expectNoObviousOverlap(
            yWorkspace.openStandardFormat,
            yWorkspace.openCarrierFormat,
            `${viewport.name} Open format controls`
        );
        await expectNoObviousOverlap(
            yWorkspace.standardOpenDropZone,
            yWorkspace.openButton,
            `${viewport.name} standard Open picker and action`
        );

        await yWorkspace.selectOpenFormat('carrier');
        await expectNoDocumentHorizontalOverflow(sessionPair.y.page, viewport.name);
        for (const [locator, label] of [
            [yWorkspace.carrierOpenPanel, `${viewport.name} carrier Open controls`],
            [yWorkspace.carrierOpenFileControl, `${viewport.name} carrier Open PNG picker`],
            [yWorkspace.carrierOpenButton, `${viewport.name} carrier Open action`],
        ]) {
            await expectViewportReachable(locator, label);
        }
        await expectNoObviousOverlap(
            yWorkspace.carrierOpenFileControl,
            yWorkspace.carrierOpenButton,
            `${viewport.name} carrier Open picker and action`
        );
    }
});

test('@phase4 p1 session workspace accessibility basics', async ({ app }) => {
    const workspace = new SessionWorkspace(app.page);
    await workspace.bootstrapAndOpenSession(
        app.runtime.entrypoint.href,
        app.profileSet.passphrase
    );

    await expect(workspace.createTab).toHaveAccessibleName(/encrypt message/i);
    await expect(workspace.openTab).toHaveAccessibleName(/open message/i);
    await expect(workspace.messageInput).toHaveAccessibleName(/^Message\b/i);
    await expect(workspace.attachmentLabel).toBeVisible();
    await expect(workspace.attachmentLabel).toContainText('Add Files');
    await expect(workspace.attachmentInput).toHaveAttribute('type', 'file');
    await expect(workspace.attachmentInput).toHaveAttribute('multiple', '');
    await expect(workspace.allowDownload).toHaveAccessibleName('Allow Saving / Downloading');
    await expect(workspace.sealButton).toHaveAccessibleName('Encrypt and download');
    await expect(workspace.createStandardFormat).toHaveAccessibleName(/\.paracci/i);
    await expect(workspace.createCarrierFormat).toHaveAccessibleName(/PNG carrier/i);

    await workspace.selectCreateFormat('carrier');
    await expect(workspace.carrierSealInput).toHaveAccessibleName('Choose PNG');
    await expect(workspace.carrierSealButton).toHaveAccessibleName(
        'Export message into PNG carrier'
    );

    await workspace.selectOpenFormat('standard');
    await expect(workspace.openButton).toHaveAccessibleName('Open and show');
    await expect(workspace.openStandardFormat).toHaveAccessibleName(/\.paracci/i);
    await expect(workspace.openCarrierFormat).toHaveAccessibleName(/PNG carrier/i);

    await workspace.selectOpenFormat('carrier');
    await expect(workspace.carrierOpenInput).toHaveAccessibleName('Choose PNG');
    await expect(workspace.carrierOpenButton).toHaveAccessibleName(
        'Extract message from PNG carrier'
    );

    await workspace.selectCreateFormat('standard');
    await workspace.createTab.focus();
    await app.page.keyboard.press('ArrowRight');
    await expect(workspace.openTab).toHaveAttribute('aria-selected', 'true');
    await expect(workspace.openPanel).toBeVisible();
    await expectVisibleFocusIndicator(workspace.openTab, 'Open tab');

    await app.page.keyboard.press('ArrowLeft');
    await expect(workspace.createTab).toHaveAttribute('aria-selected', 'true');
    await expect(workspace.createPanel).toBeVisible();
    await expectVisibleFocusIndicator(workspace.createTab, 'Create tab');

    const createCarrierUnfocused = await focusStyle(workspace.createCarrierFormat);
    await workspace.createStandardFormat.focus();
    await app.page.keyboard.press('Tab');
    await expectVisibleFocusIndicator(
        workspace.createCarrierFormat,
        'Create carrier format',
        { unfocusedStyle: createCarrierUnfocused }
    );
    await app.page.keyboard.press('Space');
    await expect(workspace.createCarrierFormat).toHaveAttribute('aria-pressed', 'true');
    await expect(workspace.carrierSealPanel).toBeVisible();

    const createCarrierTriggerUnfocused = await focusStyle(workspace.carrierSealFileTrigger);
    await app.page.keyboard.press('Tab');
    await expectVisibleFocusIndicator(
        workspace.carrierSealInput,
        'Create carrier PNG picker',
        {
            indicator: workspace.carrierSealFileTrigger,
            unfocusedStyle: createCarrierTriggerUnfocused,
        }
    );
    const createCarrierActionUnfocused = await focusStyle(workspace.carrierSealButton);
    await app.page.keyboard.press('Tab');
    await expectVisibleFocusIndicator(
        workspace.carrierSealButton,
        'Create carrier action',
        { unfocusedStyle: createCarrierActionUnfocused }
    );

    await workspace.createStandardFormat.focus();
    await app.page.keyboard.press('Enter');
    await expect(workspace.createStandardFormat).toHaveAttribute('aria-pressed', 'true');
    const sealButtonUnfocused = await focusStyle(workspace.sealButton);
    await app.page.keyboard.press('Tab');
    await expect(workspace.createCarrierFormat).toBeFocused();
    await app.page.keyboard.press('Tab');
    await expectVisibleFocusIndicator(
        workspace.sealButton,
        'Encrypt and download primary action',
        { unfocusedStyle: sealButtonUnfocused }
    );

    await workspace.createTab.focus();
    await app.page.keyboard.press('ArrowRight');
    await expect(workspace.openTab).toHaveAttribute('aria-selected', 'true');
    await expect(workspace.openPanel).toBeVisible();

    const openCarrierUnfocused = await focusStyle(workspace.openCarrierFormat);
    await workspace.openStandardFormat.focus();
    await app.page.keyboard.press('Tab');
    await expectVisibleFocusIndicator(
        workspace.openCarrierFormat,
        'Open carrier format',
        { unfocusedStyle: openCarrierUnfocused }
    );
    await app.page.keyboard.press('Space');
    await expect(workspace.openCarrierFormat).toHaveAttribute('aria-pressed', 'true');
    await expect(workspace.carrierOpenPanel).toBeVisible();

    const openCarrierTriggerUnfocused = await focusStyle(workspace.carrierOpenFileTrigger);
    await app.page.keyboard.press('Tab');
    await expectVisibleFocusIndicator(
        workspace.carrierOpenInput,
        'Open carrier PNG picker',
        {
            indicator: workspace.carrierOpenFileTrigger,
            unfocusedStyle: openCarrierTriggerUnfocused,
        }
    );
    const openCarrierActionUnfocused = await focusStyle(workspace.carrierOpenButton);
    await app.page.keyboard.press('Tab');
    await expectVisibleFocusIndicator(
        workspace.carrierOpenButton,
        'Open carrier action',
        { unfocusedStyle: openCarrierActionUnfocused }
    );

    await workspace.openStandardFormat.focus();
    await app.page.keyboard.press('Enter');
    await expect(workspace.openStandardFormat).toHaveAttribute('aria-pressed', 'true');
    const openButtonUnfocused = await focusStyle(workspace.openButton);
    await app.page.keyboard.press('Tab');
    await expect(workspace.openCarrierFormat).toBeFocused();
    await app.page.keyboard.press('Tab');
    await expectVisibleFocusIndicator(
        workspace.openButton,
        'Open and show primary action',
        { unfocusedStyle: openButtonUnfocused }
    );
});
