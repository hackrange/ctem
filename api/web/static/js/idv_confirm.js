// IDV > Expire or Revoke: the confirmation. It says what happens (the badge goes; the person must verify again with
// a government ID and a selfie; after a revoke an approver must also confirm the new pass) and offers to send the
// re-verification link now, to a contact the identity provider verified (masked). Resolves with the choice, or null.
// Everything shown goes through esc().
window.IdvConfirm = (() => {
  let dlg;
  const TEXT = {
    expire: { title: 'Expire verification', go: 'Expire verification', cls: 'btn--primary',
              what: 'It is no longer enough. Their Persona checks stay as they are.',
              after: 'When they pass a new check with a government ID and a matching selfie, the badge comes back by itself.' },
    revoke: { title: 'Revoke verification', go: 'Revoke', cls: 'btn--danger',
              what: 'Something is wrong with it. Their approved checks are declined in Persona too.',
              after: 'They can verify again, but their next pass waits in Pending for an IDV approver to confirm before the badge comes back.' },
  };

  function ask(mode, person) {
    return new Promise(resolve => {
      const t = TEXT[mode];
      if (!dlg) {
        dlg = document.createElement('dialog');
        dlg.className = 'modal';
        dlg.setAttribute('aria-labelledby', 'idvc-title');
        document.body.appendChild(dlg);
      }
      dlg.innerHTML = `<div style="padding:18px 22px;min-width:340px;max-width:560px">
        <h2 id="idvc-title" class="panel__title" style="margin:0 0 8px">${esc(t.title)}: ${esc(person.name)}</h2>
        <div class="text-sm" style="padding:10px 12px;border-radius:6px;border-left:3px solid var(--severity-high);background:var(--surface2)">
          <b>${esc(person.name)} will have to verify their identity again with a government ID and a selfie.</b>
          Their IDV badge is removed now. ${esc(t.what)} ${esc(t.after)}</div>
        <label class="text-sm" style="display:flex;gap:8px;align-items:center;margin:12px 0 4px"><input type="checkbox" id="idvc-send">
          <b>Also send a re-verification link now</b></label>
        <div id="idvc-ch" class="text-sm" hidden style="margin-left:24px">Loading their verified contacts...</div>
        <p id="idvc-msg" class="text-sm" role="status" style="min-height:1.2em;margin:8px 0 0;color:var(--severity-critical)"></p>
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:8px">
          <button type="button" class="btn btn--ghost btn--sm" data-no>Cancel</button>
          <button type="button" class="btn ${t.cls} btn--sm" data-yes>${esc(t.go)}</button></div></div>`;
      let loaded = false;
      const chBox = dlg.querySelector('#idvc-ch');
      dlg.querySelector('#idvc-send').addEventListener('change', async e => {
        chBox.hidden = !e.target.checked;
        if (!e.target.checked || loaded) return;
        loaded = true;
        try {
          const r = await fetch(`/api/v1/idv/people/${encodeURIComponent(person.id)}/contacts`, { headers: { Accept: 'application/json' }, credentials: 'same-origin' });
          const d = r.ok ? await r.json() : { channels: [], missing: ["you can't send verification links"] };
          const usable = (d.channels || []).filter(c => c.available);
          chBox.innerHTML = usable.length ? usable.map((c, i) => `<label style="display:flex;gap:8px;align-items:center;margin:4px 0">
              <input type="radio" name="idvc-ch" value="${esc(c.channel)}" data-recent="${c.recent ? 1 : ''}" ${i === 0 ? 'checked' : ''}>
              <span>${esc(c.channel === 'sms' ? 'Text' : 'Email')} to ${esc(c.shown)} <span class="text-muted">(${esc(c.source)})</span>
              ${c.recent ? '<span class="chip chip--high" style="font-size:.7rem">changed recently</span>' : ''}</span></label>`).join('')
              + `<label id="idvc-recent" style="display:none;gap:8px;align-items:flex-start;margin:6px 0;color:var(--severity-high)"><input type="checkbox" id="idvc-recent-ok">
                 <span>This contact changed recently. I confirmed it is theirs another way.</span></label>`
            : `<span class="text-muted">No verified text or email contact to send to${(d.missing || []).length ? ` (${esc(d.missing.join('; '))})` : ''}.</span>`;
          const sync = () => { const p = chBox.querySelector('input[name="idvc-ch"]:checked'); const rc = chBox.querySelector('#idvc-recent'); if (rc) rc.style.display = p && p.dataset.recent ? 'flex' : 'none'; };
          chBox.addEventListener('change', sync);
          sync();
        } catch (err) { chBox.textContent = "Couldn't load their contacts."; }
      });
      const done = v => { dlg.close(); resolve(v); };
      dlg.onclick = e => {
        if (e.target === dlg || e.target.closest('[data-no]')) { done(null); return; }
        if (!e.target.closest('[data-yes]')) return;
        const want = dlg.querySelector('#idvc-send').checked;
        const pick = want ? chBox.querySelector('input[name="idvc-ch"]:checked') : null;
        if (want && !pick) { dlg.querySelector('#idvc-msg').textContent = 'There is no contact to send to; untick "Also send" to go ahead without it.'; return; }
        const recentOk = !!(pick && pick.dataset.recent && dlg.querySelector('#idvc-recent-ok') && dlg.querySelector('#idvc-recent-ok').checked);
        if (pick && pick.dataset.recent && !recentOk) { dlg.querySelector('#idvc-msg').textContent = 'Tick the box once you have confirmed the contact.'; return; }
        done({ send: pick ? pick.value : null, confirm_recent: recentOk });
      };
      dlg.oncancel = () => resolve(null);
      dlg.showModal();
    });
  }
  return { ask };
})();
