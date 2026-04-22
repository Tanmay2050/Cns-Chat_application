/**
 * RegisterPage.js — FIXED
 *
 * CHANGES
 * ───────
 * 1. After generating keys and calling saveKeysToSession, ALSO save to
 *    localStorage keyed by the returned user.id (so the same browser /
 *    different tab can load them at login time).
 * 2. Offer a "Download key backup" JSON file immediately after registration
 *    so the user can recover on a different device.
 * 3. exportPublicKeyPEM is now called on the RSA-OAEP public key as well
 *    (was missing in the original; the server needs it for future
 *    key-wrapping operations).
 */

import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth }  from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import {
  generateRSAKeyPair,
  generateRSASignKeyPair,
  generateECDHKeyPair,
  exportPublicKeyPEM,        // unified exporter (replaces exportSignPublicKeyPEM)
  saveKeysToSession,
  saveKeysToLocal,           // NEW — see crypto.js additions
  exportKeyBackup,           // NEW — produces the downloadable JSON
} from '../utils/crypto';
import styles from './Auth.module.css';

export default function RegisterPage() {
  const [form,       setForm]       = useState({ username:'', email:'', password:'', confirm:'' });
  const [error,      setError]      = useState('');
  const [loading,    setLoading]    = useState(false);
  const [showBackup, setShowBackup] = useState(false);  // NEW
  const [backupBlob, setBackupBlob] = useState(null);   // NEW
  const { register }      = useAuth();
  const { theme, toggle } = useTheme();
  const navigate          = useNavigate();

  const handle = e => setForm(f => ({ ...f, [e.target.name]: e.target.value }));

  const submit = async e => {
    e.preventDefault();
    setError('');
    if (form.password !== form.confirm) { setError('Passwords do not match'); return; }
    if (form.password.length < 8)       { setError('Password must be at least 8 characters'); return; }
    setLoading(true);

    try {
      // 1. Generate all three key pairs client-side
      const rsaEncPair  = await generateRSAKeyPair();
      const rsaSignPair = await generateRSASignKeyPair();
      const ecdhPair    = await generateECDHKeyPair();

      // 2. Export public keys as PEM for the server
      //    FIX — original code forgot to export rsaEncPair.publicKey;
      //    the server needs it for future RSA-OAEP key-wrapping support.
      const public_key_encrypt  = await exportPublicKeyPEM(rsaEncPair.publicKey);
      const public_key          = await exportPublicKeyPEM(rsaSignPair.publicKey);  // signing
      const ecdh_public_key     = await exportPublicKeyPEM(ecdhPair.publicKey);

      // 3. Persist private keys to sessionStorage (existing behaviour)
      await saveKeysToSession(rsaEncPair, rsaSignPair, ecdhPair);

      // 4. Register with server — get back user.id
      const data = await register({
        username: form.username, email: form.email, password: form.password,
        public_key,             // RSA-PSS signing public key
        public_key_encrypt,     // RSA-OAEP encryption public key (NEW field)
        ecdh_public_key,
      });

      // FIX 1 — also save to localStorage keyed by userId so login
      //          from another tab on the same browser can find the keys
      await saveKeysToLocal(data.user.id, rsaEncPair, rsaSignPair, ecdhPair);

      // FIX 2 — prepare downloadable backup BEFORE navigating away
      const backup = await exportKeyBackup(rsaEncPair, rsaSignPair, ecdhPair, data.user.id);
      const blob   = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
      setBackupBlob(URL.createObjectURL(blob));
      setShowBackup(true);
      // Don't navigate yet — show the backup prompt first

    } catch (err) {
      setError(err.response?.data?.error || 'Registration failed');
      setLoading(false);
    }
    // Note: setLoading(false) is intentionally left for the backup-dismiss path
  };

  const dismissBackup = () => {
    setShowBackup(false);
    setLoading(false);
    navigate('/');
  };

  if (showBackup) {
    return (
      <div className={styles.page}>
        <div className={styles.card}>
          <div className={styles.logo}>🔑</div>
          <h1 className={styles.title} style={{ fontSize: 20 }}>Save Your Key Backup</h1>
          <p className={styles.subtitle}>
            Your private keys are stored only in this browser. Download a backup now — you will
            need it to log in from a different device or after clearing your browser data.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 20 }}>
            <a
              href={backupBlob}
              download={`cipherlink-keys-${form.username}.json`}
              className={styles.btn}
              style={{ textAlign: 'center', textDecoration: 'none', display: 'block', padding: '13px' }}
            >
              ⬇ Download Key Backup
            </a>
            <button onClick={dismissBackup} className={styles.btnSecondary}>
              I've saved it — continue to chat
            </button>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', textAlign: 'center' }}>
              ⚠️ Without this file, you cannot log in from other devices.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.page}>
      <button className={styles.themeBtn} onClick={toggle}>
        {theme === 'light' ? '🌙' : '☀️'}
      </button>
      <div className={styles.card}>
        <div className={styles.logo}>🔐</div>
        <h1 className={styles.title}>CipherLink</h1>
        <p className={styles.subtitle}>Create your secure account</p>
        <form onSubmit={submit} className={styles.form}>
          <div className={styles.field}>
            <label>Username</label>
            <input name="username" value={form.username} onChange={handle}
                   placeholder="Choose username" required minLength={3} />
          </div>
          <div className={styles.field}>
            <label>Email</label>
            <input name="email" type="email" value={form.email} onChange={handle}
                   placeholder="your@email.com" required />
          </div>
          <div className={styles.field}>
            <label>Password</label>
            <input name="password" type="password" value={form.password}
                   onChange={handle} placeholder="Min 8 characters" required />
          </div>
          <div className={styles.field}>
            <label>Confirm Password</label>
            <input name="confirm" type="password" value={form.confirm}
                   onChange={handle} placeholder="Repeat password" required />
          </div>
          {error   && <div className={styles.error}>{error}</div>}
          {loading && (
            <div className={styles.info}>🔑 Generating cryptographic keys — this takes a moment…</div>
          )}
          <button type="submit" className={styles.btn} disabled={loading}>
            {loading ? 'Generating Keys & Registering…' : 'Create Account'}
          </button>
        </form>
        <p className={styles.link}>
          Already have an account? <Link to="/login">Sign in</Link>
        </p>
        <div className={styles.secBadge}>🛡️ Keys generated locally — never sent to server</div>
      </div>
    </div>
  );
}
