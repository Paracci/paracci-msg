// Paracci - Preview Restrictions

function clearPreviewDomState() {
    document.querySelectorAll('img').forEach(img => {
        img.removeAttribute('src');
        img.alt = '';
    });
    document.querySelectorAll('video').forEach(video => {
        video.pause();
        video.removeAttribute('src');
        video.querySelectorAll('source').forEach(source => source.removeAttribute('src'));
        video.load();
    });
    document.querySelectorAll('.preview-text').forEach(el => {
        el.textContent = '';
    });
}

document.addEventListener('DOMContentLoaded', () => {
    const container = document.getElementById('preview-body-container');
    const allowDownload = container ? (container.dataset.allowDownload === 'true') : true;

    document.getElementById('preview-close-btn')?.addEventListener('click', () => {
        clearPreviewDomState();
        if (window.pywebview?.api?.close) {
            window.pywebview.api.close();
        } else {
            window.close();
        }
    });

    // UX-only friction for disabled downloads; it is not DRM or capture prevention.
    if (!allowDownload) {
        document.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'p' || e.key === 'c')) {
                e.preventDefault();
                return false;
            }
        });

        // Extra layer for context menu in preview mode
        document.addEventListener('contextmenu', e => e.preventDefault());
    }
});

window.addEventListener('pagehide', clearPreviewDomState);
window.addEventListener('beforeunload', clearPreviewDomState);
