// IDV > Iframe Code > Other website: the plain <iframe> and the few server lines a website needs to show the caller
// verification panel. The token stays on that website's server (an environment variable), which asks CTEM for a
// one-time panel link per page view; the browser only ever sees that link. Filled with CTEM's own address.
window.EmbedWeb = (() => {
  const html = base => `<!-- Where the panel shows. Your server fills in the src for each page view (see the server code). -->
<iframe src="{{CTEM_PANEL_URL}}" title="Caller verification" width="100%" height="560" style="border:0"
        sandbox="allow-scripts allow-same-origin" referrerpolicy="no-referrer"></iframe>

<script>
  // Optional: the panel tells this page the result. Trust it only from CTEM's exact address,
  // and treat it as a hint: your server can confirm it (GET ${base}/api/v1/idv/desk/sessions/<session>).
  window.addEventListener('message', function (e) {
    if (e.origin !== '${base}' || !e.data || e.data.type !== 'ctem.idv.result') return;
    console.log('Caller verification:', e.data.result, e.data.title);   // e.g. show it on the ticket
  });
</script>`;

  const node = base => `// Node.js (18+), e.g. in an Express route that renders the page with the panel.
// CTEM_DESK_TOKEN is the embed's token, in an environment variable, never in the page.
// ticket and analyst come from YOUR signed-in session and ticket, never from the browser.
async function ctemPanelUrl({ ticket, analyst, caller }) {
  const r = await fetch('${base}/api/v1/idv/desk/sessions', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + process.env.CTEM_DESK_TOKEN, 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ ticket, analyst, caller: caller || null }),
    signal: AbortSignal.timeout(10000),
  });
  if (!r.ok) throw new Error('CTEM caller verification: HTTP ' + r.status);
  return '${base}' + (await r.json()).launch_path;   // one-time, good for 2 minutes
}

// app.get('/tickets/:id', async (req, res) => {
//   const src = await ctemPanelUrl({ ticket: ticket.number, analyst: req.user.email, caller: ticket.callerUsername });
//   res.render('ticket', { CTEM_PANEL_URL: src });
// });`;

  const python = base => `# Python 3 (requests), e.g. in a Flask or Django view that renders the page with the panel.
# CTEM_DESK_TOKEN is the embed's token, in an environment variable, never in the page.
# ticket and analyst come from YOUR signed-in session and ticket, never from the browser.
import os, requests

def ctem_panel_url(ticket, analyst, caller=None):
    r = requests.post("${base}/api/v1/idv/desk/sessions",
                      headers={"Authorization": "Bearer " + os.environ["CTEM_DESK_TOKEN"], "Accept": "application/json"},
                      json={"ticket": ticket, "analyst": analyst, "caller": caller}, timeout=10)
    r.raise_for_status()
    return "${base}" + r.json()["launch_path"]   # one-time, good for 2 minutes

# @app.route("/tickets/<tid>")
# def ticket(tid):
#     src = ctem_panel_url(ticket=t.number, analyst=current_user.email, caller=t.caller_username)
#     return render_template("ticket.html", CTEM_PANEL_URL=src)`;

  const php = base => `<?php
// PHP 7.4+ (curl), in the page that shows the panel.
// CTEM_DESK_TOKEN is the embed's token, in an environment variable, never in the page.
// $ticket and $analyst come from YOUR signed-in session and ticket, never from the browser.
function ctem_panel_url(string $ticket, string $analyst, ?string $caller = null): string {
    $ch = curl_init('${base}/api/v1/idv/desk/sessions');
    curl_setopt_array($ch, [
        CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10,
        CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . getenv('CTEM_DESK_TOKEN'), 'Content-Type: application/json', 'Accept: application/json'],
        CURLOPT_POSTFIELDS => json_encode(['ticket' => $ticket, 'analyst' => $analyst, 'caller' => $caller]),
    ]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($code !== 200) { throw new RuntimeException("CTEM caller verification: HTTP $code"); }
    return '${base}' . json_decode($body, true)['launch_path'];   // one-time, good for 2 minutes
}
$src = ctem_panel_url($ticket['number'], $_SESSION['user_email'], $ticket['caller_username'] ?? null);
?>
<iframe src="<?= htmlspecialchars($src, ENT_QUOTES) ?>" title="Caller verification" width="100%" height="560" style="border:0"
        sandbox="allow-scripts allow-same-origin" referrerpolicy="no-referrer"></iframe>`;

  const steps = e => `On the website (a web developer, about 15 minutes):

1. Store the token above in the website server's environment as CTEM_DESK_TOKEN. Never put it in a page,
   a script file or source control.
2. Add the server code for your language: it asks CTEM for a one-time panel link each time the page loads
   (the link works once, for 2 minutes).
3. Put the iframe where the panel should show, with its src set to that link.
4. Check: open the page from the office network. The panel appears and finds the caller.

This embed works only:
  - inside ${e.frame_origin} (CTEM refuses to be framed anywhere else)
  - when the website's server calls from: ${(e.server_ips || []).join(', ')}
  - for analysts browsing from: ${(e.client_ips || []).join(', ')}
ticket: up to 40 letters, digits, dot, dash or underscore. analyst: who is signed in to the website (an email or user name).`;

  return { html, node, python, php, steps };
})();
