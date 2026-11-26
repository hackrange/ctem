// Sidebar stars: each link gets a star; a starred link shows bold, so the pages someone uses most stand out.
// Saved with the person's preferences (PATCH /api/v1/profile/prefs, starred_nav), so it follows them to any browser.
(() => {
  const PATH = /^\/[a-z0-9/_-]{0,80}$/;
  const links = () => [...document.querySelectorAll('#sidebar .sidebar__link[href]')].filter(a => !a.closest('#nav-favs'));
  let starred = new Set();

  function paint() {
    links().forEach(a => {
      const on = starred.has(a.getAttribute('href'));
      a.classList.toggle('sidebar__link--starred', on);
      const b = a.querySelector('.nav-star');
      if (b) {
        b.textContent = on ? '★' : '☆';
        b.setAttribute('aria-pressed', String(on));
        b.title = on ? 'Starred: shown bold. Click to unstar' : 'Star: show this link bold';
      }
    });
  }

  async function save() {
    try {
      await fetch('/api/v1/profile/prefs', { method: 'PATCH', credentials: 'same-origin',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify({ starred_nav: [...starred].slice(0, 40) }) });
    } catch (e) { /* stays starred on this page; saved next time */ }
  }

  function add() {
    links().forEach(a => {
      const href = a.getAttribute('href');
      if (!PATH.test(href || '') || a.querySelector('.nav-star')) return;
      const b = document.createElement('span');
      b.className = 'nav-star';
      b.setAttribute('role', 'button');
      b.setAttribute('tabindex', '0');
      const flip = e => {
        e.preventDefault();
        e.stopPropagation();
        if (starred.has(href)) starred.delete(href); else starred.add(href);
        paint();
        save();
      };
      b.addEventListener('click', flip);
      b.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') flip(e); });
      a.appendChild(b);
    });
    paint();
  }

  document.addEventListener('DOMContentLoaded', async () => {
    add();
    try {
      const r = await fetch('/api/v1/profile/prefs', { headers: { Accept: 'application/json' } });
      if (r.ok) starred = new Set(((await r.json()).prefs || {}).starred_nav || []);
    } catch (e) { /* no stars shown */ }
    paint();
  });
})();
