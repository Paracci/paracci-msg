/**
 * profile.js - Handlers for profile page interactions.
 */
document.addEventListener('DOMContentLoaded', () => {
    const colorRadios = document.querySelectorAll('input[name="avatar_color"]');
    const previewAvatar = document.querySelector('.profile-preview-card .avatar-huge');

    colorRadios.forEach(radio => {
        radio.addEventListener('change', (e) => {
            if (previewAvatar) {
                previewAvatar.style.setProperty('--avatar-bg', e.target.value);
            }
        });
    });
});
