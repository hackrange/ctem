// Cyber Threats > alert > attack path in its own tab: the story and the map at full window size (threat_graph.js).
(async () => {
  const id = new URLSearchParams(location.search).get('id') || '';
  document.getElementById('agp-back').href = ThreatView.href({ id });
  const r = await fetch(`/api/v1/threat/alerts/detail?id=${encodeURIComponent(id)}`, { headers: { Accept: 'application/json' } });
  if (!r.ok) { document.getElementById('agp-title').textContent = 'Alert not found'; return; }
  const a = await r.json();
  document.title = `Attack path: ${a.title || 'alert'} -- open-ctem`;
  ThreatGraph.render(a, ThreatView);
})();
