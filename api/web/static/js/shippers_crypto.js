// Seals a secret to one shipper's RSA key, right here in the browser. CTEM only ever sees the envelope.
// Format matches api/collector/agent/collector_crypto.py: RSA-OAEP-256 wraps an AES-256-GCM key, AAD binds it.
const ShipperCrypto = (() => {
  const enc = new TextEncoder();

  function pemToDer(pem) {
    const body = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, '').replace(/\s+/g, '');
    const bin = atob(body);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function b64(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  function hex(buf) {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function fingerprint(pem) {
    return hex(await crypto.subtle.digest('SHA-256', pemToDer(pem)));
  }

  function pretty(fp) {
    return (fp || '').toUpperCase().match(/.{1,2}/g)?.join(':') || '';
  }

  async function seal(pem, expectedFp, profileId, kind, field, secret) {
    if (!window.isSecureContext || !crypto.subtle) throw new Error('Sealing needs HTTPS');
    const der = pemToDer(pem);
    const kid = hex(await crypto.subtle.digest('SHA-256', der));
    // If what CTEM served doesn't hash to the fingerprint it claims, refuse rather than seal to a stranger
    if (kid !== expectedFp) throw new Error('Shipper key does not match its fingerprint');
    const pub = await crypto.subtle.importKey('spki', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    const cek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = enc.encode(`octem-secret-v1|${profileId}|${kind}|${field}`);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, cek, enc.encode(secret));
    const ek = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, await crypto.subtle.exportKey('raw', cek));
    return JSON.stringify({ v: 1, kid, ek: b64(ek), iv: b64(iv), ct: b64(ct) });
  }

  return { seal, fingerprint, pretty };
})();
