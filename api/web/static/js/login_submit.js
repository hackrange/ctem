// Sign-in forms: one click, one submit. The button greys out until the next page arrives, so a double click
// can't send the form twice (the server also copes if it does).
document.querySelectorAll('form[action^="/auth/"]').forEach(form => {
  form.addEventListener('submit', e => {
    if (form.dataset.sent) { e.preventDefault(); return; }
    form.dataset.sent = '1';
    const b = form.querySelector('button[type="submit"]');
    if (b) {
      b.dataset.label = b.textContent;
      b.textContent = form.action.endsWith('/auth/totp') ? 'Verifying...' : form.action.endsWith('/auth/first-password') ? 'Saving...' : 'Signing in...';
      b.disabled = true;   // after the submit event fired, so the form still goes
      b.setAttribute('aria-busy', 'true');
    }
  });
});
// Back from the next page (bfcache): make the form usable again
window.addEventListener('pageshow', e => {
  if (!e.persisted) return;
  document.querySelectorAll('form[data-sent]').forEach(form => {
    delete form.dataset.sent;
    const b = form.querySelector('button[type="submit"]');
    if (b) { b.disabled = false; b.removeAttribute('aria-busy'); if (b.dataset.label) b.textContent = b.dataset.label; }
  });
});
