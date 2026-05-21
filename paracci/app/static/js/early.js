// Silence "AbortError: Transition was skipped" uncaught promise rejections from View Transitions API
window.addEventListener('unhandledrejection', event => {
    if (event.reason && (event.reason.name === 'AbortError' || event.reason.message === 'Transition was skipped')) {
        event.preventDefault();
    }
});
