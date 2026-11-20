// Shared bits for the Cyber Threats list and alert pages. Everything goes through esc().
(function () {
  const SOURCES = { CS: 'CrowdStrike', R7: 'Rapid7', SPL: 'Splunk', S1: 'SentinelOne', MDE: 'Microsoft Defender',
                    XDR: 'Cortex XDR', GC: 'Guardicore', FGT: 'Fortinet', PAN: 'Palo Alto NGFW' };
  const SEV = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };
  const muted = '<span class="text-muted">--</span>';
  const label = s => s ? s.charAt(0).toUpperCase() + s.slice(1).replace(/_/g, ' ') : '';

  // ATT&CK pages live at /techniques/T1059/001/ for sub-techniques
  const mitreUrl = id => `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;

  window.ThreatView = {
    href: a => `/threat/alert?id=${encodeURIComponent(a.id)}`,
    sourceChip: a => `<span class="chip chip--info" style="font-size:.7rem" title="${esc(SOURCES[a.source_code] || a.source || '')}">${esc(a.source_code || '?')}</span>`,
    sourceName: a => SOURCES[a.source_code] || a.source || '--',
    sevChip: s => s ? `<span class="chip chip--${SEV[s] || 'info'}">${esc(label(s))}</span>` : muted,
    statusLabel: label,
    statusChip: s => s ? `<span class="chip chip--${s === 'closed' ? 'low' : s === 'new' ? 'high' : 'info'}">${esc(label(s))}</span>` : muted,
    device: a => a.device_id
      ? `<a class="dt-link" href="/devices/${encodeURIComponent(a.device_id)}">${esc(a.hostname)}</a>`
      : (a.hostname ? esc(a.hostname) : muted),
    mitre: a => {
      if (a.technique_id) {
        return `<a class="dt-link text-mono text-sm" href="${esc(mitreUrl(a.technique_id))}" target="_blank" rel="noopener noreferrer" title="${esc(a.technique || '')}">${esc(a.technique_id)}</a>`;
      }
      return a.technique ? `<span class="text-sm">${esc(a.technique)}</span>` : muted;
    },
    mitreUrl,
    tacticUrl: id => `https://attack.mitre.org/tactics/${id}/`,
    when: a => a.detected_at
      ? `<span class="text-sm" title="${a.detected_estimated ? 'First seen by CTEM; the source sent no detection time' : ''}">${esc(new Date(a.detected_at).toLocaleString())}${a.detected_estimated ? ' *' : ''}</span>`
      : muted,
  };
})();
