// Paracci - Preview Restrictions

document.addEventListener('DOMContentLoaded', () => {
    const container = document.getElementById('preview-body-container');
    const allowDownload = container ? (container.dataset.allowDownload === 'true') : true;

    // Prevent standard copy/save/print shortcuts if download is disabled
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
