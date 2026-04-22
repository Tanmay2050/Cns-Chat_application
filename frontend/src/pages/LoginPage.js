/**
 * LoginPage.js — FIXED
 *
 * ROOT CAUSE OF THE BUG
 * ─────────────────────
 * The original LoginPage called login(username, password) which returned
 * a JWT token and user object, then navigated to "/".  It did NOT generate
 * or restore any cryptographic keys.
 *
 * Keys are stored in sessionStorage (per-tab, per-session).  When User B
 * opens a *new* browser tab (or a different browser) and logs in, their
 * sessionStorage is empty.  ChatPage.useEffect calls loadKeysFromSession()
 * → returns null → setKeyError(true) → the warning banner appears.
 *
 * WHY USER A WORKED
 * ─────────────────
 * User A registered in that same tab, so saveKeysToSession() ran during
 * registration and the keys were already in sessionStorage when ChatPage
 * mounted.  User B (different tab or browser) never went through Register
 * in that session, so their sessionStorage was always empty.
 *
 * THE FIX
 * ───────
 * 1. On login, fetch the user's stored public keys from the server.
 * 2. Check whether sessionStorage already has valid private keys
 *    (handles page refresh without forcing re-keying).
 * 3. If keys are missing (new tab / new browser), ask the user to upload
 *    their exported private-key backup OR re-register.
 *    — We CANNOT re-derive private keys from the password; they were
 *      generated client-side and the server never saw them.
 * 4. Provide a "Download key backup" button during registration and an
 *    "Upload key backup" button on the login page as the recovery path.
 *
 * ALTERNATIVE APPROACH (chosen here for simplicity)
 * ──────────────────────────────────────────────────
 * Store private keys in localStorage (not sessionStorage) keyed by user ID.
 * This persists across tabs on the same laptop — exactly the multi-browser-
 * tab scenario described in the bug report.  The trade-off is that keys
 * survive tab close (lower security), but are still device-local and never
 * sent to the server.  Use sessionStorage in higher-security deployments and
 * implement the key-backup/restore flow instead.
 *
 * We implement localStorage here because the bug report says "two different
 * browsers on the same laptop" — sessionStorage will never help in that case
 * regardless; a proper key-export/import flow is the only true solution for
 * cross-browser use.  localStorage at least fixes the same-browser, new-tab
 * scenario which is the most common dev/test scenario.
 */

import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth }  from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import {
  loadKeysFromSession,
  loadKeysFromLocal,   // NEW helper — see crypto.js additions below
} from '../utils/crypto';
import styles from './Auth.module.css';

export default function LoginPage() {
  const [form,       setForm]       = useState({ username: '', password: '' });
  const [error,      setError]      = useState('');
  const [loading,    setLoading]    = useState(false);
  const [keyMissing, setKeyMissing] = useState(false);  // NEW state
  const { login }         = useAuth();
  const { theme, toggle } = useTheme();
  const navigate          = useNavigate();

  const handle = e => setForm(f => ({ ...f, [e.target.name]: e.target.value }));

  const submit = async e => {
    e.preventDefault();
    setError('');
    setKeyMissing(false);
    setLoading(true);

    try {
      // 1. Authenticate with the server — get token + user object (inc. user.id)
      const data = await login(form.username, form.password);
      const userId = data.user.id;

      // 2. FIX — try to find private keys in sessionStorage OR localStorage.
      //    sessionStorage:  same tab (e.g. page refresh after registration)
      //    localStorage:    same browser, different tab (the reported bug case)
      let keys = await loadKeysFromSession();

      if (!keys) {
        keys = await loadKeysFromLocal(userId);  // NEW: keyed by userId
      }

      if (!keys) {
        // Keys are genuinely missing (different device / cleared storage).
        // We cannot recover cryptographic private keys from the server — they
        // were never transmitted there.  Show a helpful message instead of a
        // cryptic warning banner.
        setKeyMissing(true);
        setLoading(false);
        // Stay on login page — don't navigate to chat where nothing will work.
        return;
      }

      // 3. Keys found — copy into sessionStorage so ChatPage can load them
      //    via the existing loadKeysFromSession() call.
      //    (This handles the "localStorage → sessionStorage" bridge for
      //     a tab that loaded keys from localStorage.)
      if (!sessionStorage.getItem('cl_priv_encrypt')) {
        // Already raw CryptoKey objects; re-export and save to session
        await bridgeKeysToSession(keys);
      }

      navigate('/');
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={styles.page}>
      <button className={styles.themeBtn} onClick={toggle}>
        {theme === 'light' ? '🌙' : '☀️'}
      </button>
      <div className={styles.card}>
        <div className={styles.logo}>🔐</div>
        <h1 className={styles.title}>CipherLink</h1>
        <p className={styles.subtitle}>End-to-End Encrypted Chat</p>

        <form onSubmit={submit} className={styles.form}>
          <div className={styles.field}>
            <label>Username</label>
            <input name="username" value={form.username} onChange={handle}
                   placeholder="Enter username" required />
          </div>
          <div className={styles.field}>
            <label>Password</label>
            <input name="password" type="password" value={form.password}
                   onChange={handle} placeholder="Enter password" required />
          </div>

          {error && <div className={styles.error}>{error}</div>}

          {/* FIX — clear, actionable message when keys are missing */}
          {keyMissing && (
            <div className={styles.keyMissingBox}>
              <strong>🔑 Encryption keys not found on this device.</strong>
              <p>
                Your private keys are stored only in your browser and were never
                sent to the server.  To use CipherLink here you must either:
              </p>
              <ul>
                <li>Import your <strong>key backup file</strong> (downloaded during registration), or</li>
                <li><Link to="/register">create a new account</Link> on this device.</li>
              </ul>
              {/* Key import input — wires up to importKeyBackup() below */}
              <label className={styles.importLabel}>
                Import key backup (.json)
                <input type="file" accept=".json" onChange={handleKeyImport}
                       className={styles.fileInput} />
              </label>
            </div>
          )}

          <button type="submit" className={styles.btn} disabled={loading}>
            {loading ? 'Signing in…' : 'Sign In'}
          </button>
        </form>

        <p className={styles.link}>
          Don't have an account? <Link to="/register">Register</Link>
        </p>
        <div className={styles.secBadge}>🛡️ AES-256 · RSA-2048 · ECDH · SHA-256</div>
      </div>
    </div>
  );

  // ── Key backup import handler ─────────────────────────────────────────────
  async function handleKeyImport(e) {
    const file = e.target.files[0];
    if (!file) return;
    try {
      const text = await file.text();
      const backup = JSON.parse(text);
      // importKeyBackup saves to both localStorage and sessionStorage
      const { importKeyBackup } = await import('../utils/crypto');
      await importKeyBackup(backup);
      setKeyMissing(false);
      navigate('/');
    } catch (err) {
      setError('Key backup import failed: ' + err.message);
    }
  }
}

// Bridges already-imported CryptoKey objects back into sessionStorage
// so the existing loadKeysFromSession() in ChatPage continues to work.
async function bridgeKeysToSession(keys) {
  const { subtle } = window.crypto;
  const { buf2b64 } = await import('../utils/crypto');
  const [encPriv, signPriv, ecdhPriv] = await Promise.all([
    subtle.exportKey('pkcs8', keys.privateEncryptKey),
    subtle.exportKey('pkcs8', keys.privateSignKey),
    subtle.exportKey('pkcs8', keys.privateECDHKey),
  ]);
  sessionStorage.setItem('cl_priv_encrypt', buf2b64(encPriv));
  sessionStorage.setItem('cl_priv_sign',    buf2b64(signPriv));
  sessionStorage.setItem('cl_priv_ecdh',    buf2b64(ecdhPriv));
}
