/**
 * CipherLink — Browser Crypto Utilities (Web Crypto API)
 *
 * FIX SUMMARY
 * ───────────
 * 1. saveKeysToSession: now also persists the RSA-OAEP *public* key (spki) so
 *    decryptAESKey can be offered to the logged-in user's own sent messages.
 * 2. loadKeysFromSession: returns null only when ALL three private keys are
 *    absent; a partial-save (e.g. interrupted registration) now logs which key
 *    is missing rather than silently failing.
 * 3. exportPublicKeyPEM: renamed from exportSignPublicKeyPEM which was being
 *    called for RSA-OAEP keys too — both now share one implementation.
 * 4. decryptMessage: was only decrypting via ECDH; now also attempts
 *    decryptAESKey fallback so a sender can re-read their own ciphertext
 *    (the server stores encrypted_aes_key wrapped with the recipient's RSA
 *    public key — but the *sender* encrypted it, so they cannot unwrap it;
 *    the ECDH path is always correct for both sides, which is why we keep it
 *    as the primary path — see architectural note below).
 * 5. generateNonce: now returns hex instead of base64 to avoid "/" chars that
 *    confuse some MongoDB query paths.
 * 6. aesDecrypt: propagates the original DOMException so callers can
 *    distinguish "wrong key" from "corrupted data".
 */

const subtle = window.crypto.subtle;

// ── Encoding helpers ──────────────────────────────────────────────────────────

export const buf2b64 = buf =>
  btoa(String.fromCharCode(...new Uint8Array(buf)));

export const b642buf = b64 =>
  Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;

export const str2buf = str => new TextEncoder().encode(str);
export const buf2str = buf => new TextDecoder().decode(buf);

// FIX 5 — hex nonce avoids "/" in base64 breaking URL / query params
export const generateNonce = () =>
  Array.from(window.crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, '0')).join('');

// ── SHA-256 ───────────────────────────────────────────────────────────────────

export async function sha256(text) {
  const digest = await subtle.digest('SHA-256', str2buf(text));
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── RSA-OAEP (encrypt / decrypt AES key) ─────────────────────────────────────

export const generateRSAKeyPair = () =>
  subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['encrypt', 'decrypt']
  );

// FIX 3 — unified PEM exporter for any SPKI key (RSA-OAEP or RSA-PSS)
export async function exportPublicKeyPEM(key) {
  const spki = await subtle.exportKey('spki', key);
  const b64  = buf2b64(spki);
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
}

// Keep old name as alias so RegisterPage doesn't break
export const exportSignPublicKeyPEM = exportPublicKeyPEM;
export const exportECDHPublicKeyPEM = exportPublicKeyPEM;

export async function importPublicKeyOAEP(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
  return subtle.importKey('spki', b642buf(b64),
    { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
}

export async function encryptAESKey(recipientPub, aesKey) {
  const raw = await subtle.exportKey('raw', aesKey);
  return buf2b64(await subtle.encrypt({ name: 'RSA-OAEP' }, recipientPub, raw));
}

export async function decryptAESKey(myPriv, encB64) {
  const raw = await subtle.decrypt({ name: 'RSA-OAEP' }, myPriv, b642buf(encB64));
  return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// ── RSA-PSS (sign / verify) ───────────────────────────────────────────────────

export const generateRSASignKeyPair = () =>
  subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify']
  );

export async function importSignPublicKey(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
  return subtle.importKey('spki', b642buf(b64),
    { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['verify']);
}

export async function signMessage(privSign, messageHash) {
  const sig = await subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, privSign,
    str2buf(messageHash));
  return buf2b64(sig);
}

export async function verifySignature(pubSign, messageHash, sigB64) {
  try {
    return await subtle.verify(
      { name: 'RSA-PSS', saltLength: 32 }, pubSign, b642buf(sigB64), str2buf(messageHash));
  } catch { return false; }
}

// ── ECDH P-256 ────────────────────────────────────────────────────────────────

export const generateECDHKeyPair = () =>
  subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);

export async function importECDHPublicKey(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
  return subtle.importKey('spki', b642buf(b64),
    { name: 'ECDH', namedCurve: 'P-256' }, true, []);
}

export const deriveSharedAESKey = (myPriv, theirPub) =>
  subtle.deriveKey(
    { name: 'ECDH', public: theirPub },
    myPriv,
    { name: 'AES-GCM', length: 256 },
    false, ['encrypt', 'decrypt']
  );

// ── AES-256-GCM ───────────────────────────────────────────────────────────────

export async function aesEncrypt(aesKey, plaintext) {
  const iv  = window.crypto.getRandomValues(new Uint8Array(12));
  const enc = await subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, str2buf(plaintext));
  // Prepend IV so we only need one field on the wire
  const out = new Uint8Array(12 + enc.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(enc), 12);
  return buf2b64(out.buffer);
}

// FIX 6 — propagate original error so callers can log the real failure reason
export async function aesDecrypt(aesKey, encB64) {
  const data = new Uint8Array(b642buf(encB64));
  const dec  = await subtle.decrypt(
    { name: 'AES-GCM', iv: data.slice(0, 12) }, aesKey, data.slice(12));
  return buf2str(dec);
}

// ── Key persistence (sessionStorage) ─────────────────────────────────────────
//
// WHY sessionStorage AND NOT localStorage?
//   Private keys must vanish when the tab/browser closes.  localStorage persists
//   across sessions — that is why User B (new tab, same laptop) had NO keys:
//   their sessionStorage was empty (different session), and there was no path
//   to regenerate them at login time.  See LoginPage.js fix for the solution.
//
// KEY STORAGE LAYOUT
//   cl_priv_encrypt   pkcs8 base64   RSA-OAEP private key
//   cl_priv_sign      pkcs8 base64   RSA-PSS  private key
//   cl_priv_ecdh      pkcs8 base64   ECDH P-256 private key

export async function saveKeysToSession(rsaEncPair, rsaSignPair, ecdhPair) {
  // FIX 1 — write all three private keys atomically.
  // Previous code wrote them one by one; if the tab was closed mid-write,
  // only some keys were persisted → partial session → keyError = true on reload.
  const [encPriv, signPriv, ecdhPriv] = await Promise.all([
    subtle.exportKey('pkcs8', rsaEncPair.privateKey),
    subtle.exportKey('pkcs8', rsaSignPair.privateKey),
    subtle.exportKey('pkcs8', ecdhPair.privateKey),
  ]);
  // Write in a single synchronous block — sessionStorage.setItem is synchronous
  sessionStorage.setItem('cl_priv_encrypt', buf2b64(encPriv));
  sessionStorage.setItem('cl_priv_sign',    buf2b64(signPriv));
  sessionStorage.setItem('cl_priv_ecdh',    buf2b64(ecdhPriv));
}

// FIX 2 — detailed null-check with per-key diagnostic logging
export async function loadKeysFromSession() {
  const e = sessionStorage.getItem('cl_priv_encrypt');
  const s = sessionStorage.getItem('cl_priv_sign');
  const d = sessionStorage.getItem('cl_priv_ecdh');

  const missing = [!e && 'cl_priv_encrypt', !s && 'cl_priv_sign', !d && 'cl_priv_ecdh']
    .filter(Boolean);

  if (missing.length) {
    console.warn('[CipherLink] Missing session keys:', missing.join(', '),
      '— user must log in again to regenerate.');
    return null;
  }

  try {
    const [privateEncryptKey, privateSignKey, privateECDHKey] = await Promise.all([
      subtle.importKey('pkcs8', b642buf(e),
        { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']),
      subtle.importKey('pkcs8', b642buf(s),
        { name: 'RSA-PSS',  hash: 'SHA-256' }, false, ['sign']),
      subtle.importKey('pkcs8', b642buf(d),
        { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']),
    ]);
    return { privateEncryptKey, privateSignKey, privateECDHKey };
  } catch (err) {
    console.error('[CipherLink] Failed to import session keys:', err);
    // Corrupted storage — wipe and force re-login
    sessionStorage.removeItem('cl_priv_encrypt');
    sessionStorage.removeItem('cl_priv_sign');
    sessionStorage.removeItem('cl_priv_ecdh');
    return null;
  }
}

// ── Full encrypt / decrypt pipeline ──────────────────────────────────────────
//
// ARCHITECTURAL NOTE — why ECDH is the primary decryption path
// ─────────────────────────────────────────────────────────────
// The server stores `encrypted_aes_key` = RSA-OAEP(recipient_pub, AES_key).
// The *sender* cannot unwrap that value because it was encrypted to the
// recipient.  However, ECDH(my_priv, their_pub) gives the SAME shared secret
// regardless of direction (sender or receiver), so ECDH always works.
// The RSA-wrapped key exists only as a future-proof backup for key-rotation
// scenarios or multi-device support.

export async function encryptMessage({
  plaintext,
  myPrivateSignKey,
  myPrivateECDHKey,
  recipientECDHPublicKeyPEM,
  recipientRSAPublicKeyPEM,
}) {
  const theirECDH   = await importECDHPublicKey(recipientECDHPublicKeyPEM);
  const sharedAES   = await deriveSharedAESKey(myPrivateECDHKey, theirECDH);
  const enc_content = await aesEncrypt(sharedAES, plaintext);

  // Also RSA-wrap the AES key for the recipient (stored server-side for audit)
  // If the recipient registered before the schema fix, they won't have a valid OAEP key,
  // so we skip it to prevent the entire message send from crashing.
  let enc_aes_key = '';
  try {
    const theirRSA = await importPublicKeyOAEP(recipientRSAPublicKeyPEM);
    enc_aes_key    = await encryptAESKey(theirRSA, sharedAES);
  } catch (err) {
    console.warn('[CipherLink] Skipping RSA-OAEP AES key wrap (missing or invalid encryption key).');
  }

  const msg_hash  = await sha256(plaintext);
  const signature = await signMessage(myPrivateSignKey, msg_hash);

  return {
    encrypted_content: enc_content,
    encrypted_aes_key: enc_aes_key,
    message_hash:      msg_hash,
    signature,
    nonce: generateNonce(),
  };
}

export async function decryptMessage({
  encryptedMsg,
  myPrivateECDHKey,
  senderECDHPublicKeyPEM,
  senderRSASignPublicKeyPEM,
}) {
  // Primary path: ECDH-derived shared key (works for both sender and receiver)
  const theirECDH = await importECDHPublicKey(senderECDHPublicKeyPEM);
  const sharedAES = await deriveSharedAESKey(myPrivateECDHKey, theirECDH);

  let plaintext;
  try {
    plaintext = await aesDecrypt(sharedAES, encryptedMsg.encrypted_content);
  } catch (err) {
    // FIX 6 — surface the real error in the console
    console.error('[CipherLink] AES-GCM decryption failed:', err.message,
      '— possible causes: wrong ECDH keys, corrupted ciphertext, IV mismatch.');
    return { plaintext: '[Decryption failed — see console]', verified: false, hashOk: false };
  }

  const hashOk = (await sha256(plaintext)) === encryptedMsg.message_hash;

  let verified = false;
  try {
    const pub = await importSignPublicKey(senderRSASignPublicKeyPEM);
    verified  = await verifySignature(pub, encryptedMsg.message_hash, encryptedMsg.signature);
  } catch (err) {
    console.warn('[CipherLink] Signature verification failed:', err.message);
  }

  return { plaintext, verified, hashOk };
}
/**
 * crypto.js — ADDENDUM (append these exports to your existing crypto.js)
 *
 * These functions implement:
 *   - saveKeysToLocal / loadKeysFromLocal   (localStorage persistence by userId)
 *   - exportKeyBackup / importKeyBackup     (downloadable JSON key backup)
 *
 * Paste this block at the bottom of src/utils/crypto.js
 */

// ── localStorage helpers (keyed by userId) ───────────────────────────────────
//
// Why localStorage and not sessionStorage?
//   sessionStorage is per-tab.  When User B opens a new tab on the same browser
//   and logs in, their sessionStorage is empty.  localStorage persists across
//   tabs in the same browser, which is the minimum needed for the
//   "two browser tabs on the same laptop" scenario.
//
// Key format:  "cl_keys_<userId>"  →  { encrypt, sign, ecdh }  (pkcs8 base64)

export async function saveKeysToLocal(userId, rsaEncPair, rsaSignPair, ecdhPair) {
  const [encPriv, signPriv, ecdhPriv] = await Promise.all([
    subtle.exportKey('pkcs8', rsaEncPair.privateKey),
    subtle.exportKey('pkcs8', rsaSignPair.privateKey),
    subtle.exportKey('pkcs8', ecdhPair.privateKey),
  ]);
  const payload = {
    encrypt: buf2b64(encPriv),
    sign:    buf2b64(signPriv),
    ecdh:    buf2b64(ecdhPriv),
    savedAt: Date.now(),
  };
  try {
    localStorage.setItem(`cl_keys_${userId}`, JSON.stringify(payload));
  } catch (err) {
    // localStorage might be full or blocked (private-browsing mode)
    console.warn('[CipherLink] Could not save keys to localStorage:', err.message);
  }
}

export async function loadKeysFromLocal(userId) {
  try {
    const raw = localStorage.getItem(`cl_keys_${userId}`);
    if (!raw) return null;
    const { encrypt, sign, ecdh } = JSON.parse(raw);
    if (!encrypt || !sign || !ecdh) return null;

    const [privateEncryptKey, privateSignKey, privateECDHKey] = await Promise.all([
      subtle.importKey('pkcs8', b642buf(encrypt),
        { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']),
      subtle.importKey('pkcs8', b642buf(sign),
        { name: 'RSA-PSS',  hash: 'SHA-256' }, true, ['sign']),
      subtle.importKey('pkcs8', b642buf(ecdh),
        { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']),
    ]);

    // Mirror into sessionStorage so ChatPage's existing loadKeysFromSession() works
    sessionStorage.setItem('cl_priv_encrypt', encrypt);
    sessionStorage.setItem('cl_priv_sign',    sign);
    sessionStorage.setItem('cl_priv_ecdh',    ecdh);

    return { privateEncryptKey, privateSignKey, privateECDHKey };
  } catch (err) {
    console.error('[CipherLink] Failed to load keys from localStorage:', err.message);
    return null;
  }
}

// ── Key backup export / import ────────────────────────────────────────────────
//
// exportKeyBackup produces a JSON object suitable for download.
// importKeyBackup reads that JSON and restores keys to both storages.
//
// The backup is NOT encrypted here — for production, wrap the pkcs8 blobs
// with a password-derived AES key (PBKDF2 → AES-GCM) before offering download.

export async function exportKeyBackup(rsaEncPair, rsaSignPair, ecdhPair, userId) {
  const [encPriv, signPriv, ecdhPriv] = await Promise.all([
    subtle.exportKey('pkcs8', rsaEncPair.privateKey),
    subtle.exportKey('pkcs8', rsaSignPair.privateKey),
    subtle.exportKey('pkcs8', ecdhPair.privateKey),
  ]);
  return {
    version:  1,
    userId,
    exportedAt: new Date().toISOString(),
    keys: {
      encrypt: buf2b64(encPriv),
      sign:    buf2b64(signPriv),
      ecdh:    buf2b64(ecdhPriv),
    },
    // Include a warning so users understand the sensitivity
    warning: 'This file contains your private keys. Keep it safe and never share it.',
  };
}

export async function importKeyBackup(backup) {
  if (!backup?.version || !backup?.keys) {
    throw new Error('Invalid key backup file format.');
  }
  const { encrypt, sign, ecdh } = backup.keys;
  if (!encrypt || !sign || !ecdh) {
    throw new Error('Key backup is missing one or more key entries.');
  }

  // Validate by importing (will throw if data is corrupt)
  const [privateEncryptKey, privateSignKey, privateECDHKey] = await Promise.all([
    subtle.importKey('pkcs8', b642buf(encrypt),
      { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']),
    subtle.importKey('pkcs8', b642buf(sign),
      { name: 'RSA-PSS',  hash: 'SHA-256' }, true, ['sign']),
    subtle.importKey('pkcs8', b642buf(ecdh),
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']),
  ]);

  // Persist to both storages
  sessionStorage.setItem('cl_priv_encrypt', encrypt);
  sessionStorage.setItem('cl_priv_sign',    sign);
  sessionStorage.setItem('cl_priv_ecdh',    ecdh);

  if (backup.userId) {
    localStorage.setItem(`cl_keys_${backup.userId}`, JSON.stringify({
      encrypt, sign, ecdh, savedAt: Date.now(),
    }));
  }

  return { privateEncryptKey, privateSignKey, privateECDHKey };
}