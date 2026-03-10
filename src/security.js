import crypto from 'node:crypto';

function hmacHex(secret, payload) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

function safeEqualHex(a, b) {
  try {
    const ba = Buffer.from(String(a || ''), 'hex');
    const bb = Buffer.from(String(b || ''), 'hex');
    if (ba.length === 0 || bb.length === 0 || ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}

export function verifySignedPairRequest({ secret, pairingCode, backendUrl, expiresAt, nonce, signature }) {
  if (!secret) return { ok: false, error: 'AGENT_PAIR_SECRET is not configured' };
  if (!pairingCode || !backendUrl || !expiresAt || !nonce || !signature) {
    return { ok: false, error: 'Missing signed pairing fields' };
  }

  const expiryMs = Date.parse(String(expiresAt));
  if (Number.isNaN(expiryMs)) return { ok: false, error: 'Invalid expiresAt format' };
  if (Date.now() > expiryMs) return { ok: false, error: 'Pair request expired' };

  const payload = `${pairingCode}|${backendUrl}|${expiresAt}|${nonce}`;
  const expected = hmacHex(secret, payload);
  if (!safeEqualHex(expected, signature)) {
    return { ok: false, error: 'Invalid signature' };
  }

  return { ok: true };
}

export function signPairRequestForTesting({ secret, pairingCode, backendUrl, expiresAt, nonce }) {
  const payload = `${pairingCode}|${backendUrl}|${expiresAt}|${nonce}`;
  return hmacHex(secret, payload);
}
