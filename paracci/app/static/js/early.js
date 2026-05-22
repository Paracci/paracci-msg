// Silence "AbortError: Transition was skipped" uncaught promise rejections from View Transitions API
window.addEventListener('unhandledrejection', event => {
    if (event.reason && (event.reason.name === 'AbortError' || event.reason.message === 'Transition was skipped')) {
        event.preventDefault();
    }
});

// Apply initial sidebar collapsed state immediately when body is created to avoid layout flash / view transition glitches
(function applyEarlySidebarState() {
    if (localStorage.getItem('paracci_sidebar_collapsed') === 'true') {
        if (document.body) {
            document.body.classList.add('sidebar-collapsed');
        } else {
            const observer = new MutationObserver((mutations, obs) => {
                if (document.body) {
                    document.body.classList.add('sidebar-collapsed');
                    obs.disconnect();
                }
            });
            observer.observe(document.documentElement, { childList: true, subtree: true });
        }
    }
})();
