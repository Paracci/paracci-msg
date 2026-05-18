document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('report-back-btn')?.addEventListener('click', () => history.back());

  const rawContentTag = document.getElementById('raw-content');
  const container = document.getElementById('markdown-container');
  if (!rawContentTag || !container) return;

  const rawContent = rawContentTag.innerHTML;
  if (typeof marked !== 'undefined') {
    try {
      container.innerHTML = marked.parse(rawContent);
      container.classList.add('fade-in');
    } catch (e) {
      container.innerHTML = `<div class="text-error">${window.PARACCI_I18N?.render_error || 'Report could not be rendered.'}</div><pre>${rawContent}</pre>`;
    }
  } else {
    container.innerHTML = `<div class="text-error">${window.PARACCI_I18N?.marked_missing || 'Markdown renderer not loaded.'}</div><pre>${rawContent}</pre>`;
  }
});
