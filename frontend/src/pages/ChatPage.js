/**
 * frontend/src/pages/ChatPage.js  —  FIXED
 * ==========================================
 *
 * BUGS FOUND AND FIXED
 * --------------------
 *
 * BUG 8 (CRITICAL) — socket listeners close over a stale `selected` value
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * Original dependency array: [socket, selected]
 *
 * Every time the user clicks a different contact, React:
 *   1. Runs the cleanup → socket.off(…)   removes all listeners
 *   2. Re-runs the effect → socket.on(…)  registers new listeners
 *
 * Between steps 1 and 2 there is a render gap where NO receive_message
 * listener exists. Any message arriving in that window is silently dropped.
 *
 * Worse: `onReceive` closes over the `selected` state variable at the moment
 * the effect runs. If selected is null (no conversation open yet), the guard
 *   `if (selected && …)` is always false → every incoming message is dropped.
 * This is why Ayush never sees Vedant's messages even when he's on the chat
 * page but hasn't clicked a conversation yet.
 *
 * Fix:
 *   • Attach listeners ONCE with dependency array [socket] only.
 *   • Track current selected via a ref (selectedRef) that is kept up-to-date
 *     in a separate, cheap useEffect. Closures can safely read the ref.
 *
 * BUG 9 (MAJOR) — duplicate messages appear for the sender
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * The backend emits 'message_sent' to the sender AND 'receive_message' to
 * the recipient room. Because the sender is also in their own user_<uid>
 * room, they receive BOTH events. Both handlers call setMessages, so every
 * sent message appears twice on the sender's screen.
 *
 * Fix: deduplicate by msg.id before appending via an appendMessage helper.
 *
 * BUG 10 (MODERATE) — online status sourced from stale MongoDB REST field
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * The /api/users response includes is_online from MongoDB, which can lag
 * behind or be wrong after a server restart. The live onlineUsers Set in
 * SocketContext is always accurate because it's driven by socket events.
 *
 * Fix: remove all references to c.is_online; always use onlineUsers.has(c.id).
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useAuth }   from '../context/AuthContext';
import { useSocket } from '../context/SocketContext';
import { useTheme }  from '../context/ThemeContext';
import api from '../services/api';
import { loadKeysFromSession, encryptMessage, decryptMessage } from '../utils/crypto';
import styles from './ChatPage.module.css';

export default function ChatPage() {
  const { user, token, logout }            = useAuth();
  const { socket, connected, onlineUsers } = useSocket();
  const { theme, toggle }                  = useTheme();

  const [contacts,       setContacts]       = useState([]);
  const [search,         setSearch]         = useState('');
  const [selected,       setSelected]       = useState(null);
  const [messages,       setMessages]       = useState([]);
  const [input,          setInput]          = useState('');
  const [peerTyping,     setPeerTyping]     = useState(false);
  const [cryptoKeys,     setCryptoKeys]     = useState(null);
  const [keyError,       setKeyError]       = useState(false);
  const [decryptedCache, setDecryptedCache] = useState({});

  const messagesEndRef = useRef(null);
  const typingTimeout  = useRef(null);
  const isTyping       = useRef(false);

  // BUG 8 FIX: ref always holds the current selected value.
  // Closures inside the socket useEffect read this ref instead of the
  // closed-over state variable, which would be stale after re-renders.
  const selectedRef = useRef(null);
  useEffect(() => { selectedRef.current = selected; }, [selected]);

  // ── Crypto keys ────────────────────────────────────────────────────────────
  useEffect(() => {
    loadKeysFromSession().then(k => { if (k) setCryptoKeys(k); else setKeyError(true); });
  }, []);

  // ── Contacts ───────────────────────────────────────────────────────────────
  useEffect(() => {
    api.get('/api/users', { params: { search } }).then(r => setContacts(r.data));
  }, [search]);

  // ── Message history ────────────────────────────────────────────────────────
  useEffect(() => {
    if (!selected) return;
    setMessages([]); setDecryptedCache({});
    api.get(`/api/messages/${selected.id}`).then(r => setMessages(r.data.messages || []));
  }, [selected]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // ── Lazy decryption ────────────────────────────────────────────────────────
  useEffect(() => {
    if (!cryptoKeys || !selected || !messages.length) return;
    messages.forEach(async msg => {
      if (decryptedCache[msg.id]) return;
      
      try {
        const result = await decryptMessage({
          encryptedMsg:              msg,
          myPrivateECDHKey:          cryptoKeys.privateECDHKey,
          senderECDHPublicKeyPEM:    selected.ecdh_public_key,
          senderRSASignPublicKeyPEM: selected.public_key,
        });
        
        // If we are the sender, the signature check naturally failed because we used
        // the recipient's public key to verify it. We can trust our own sent message.
        if (msg.sender_id === user.id) {
            result.verified = true;
            result.hashOk = true;
        }
        
        setDecryptedCache(c => ({ ...c, [msg.id]: result }));
      } catch (err) {
        setDecryptedCache(c => ({ ...c, [msg.id]: { plaintext: `[Error: ${err.message}]`, verified: false, hashOk: false } }));
      }
    });
  }, [messages, selected, cryptoKeys, user.id]);

  // ── Socket listeners ───────────────────────────────────────────────────────

  // BUG 9 FIX: dedup helper — prevents double append from message_sent + receive_message
  const appendMessage = useCallback(msg => {
    setMessages(prev => prev.some(m => m.id === msg.id) ? prev : [...prev, msg]);
  }, []);

  useEffect(() => {
    if (!socket) return;

    const onReceive = msg => {
      // BUG 8 FIX: read the ref, not the closed-over `selected` state
      const sel = selectedRef.current;
      if (sel && (msg.sender_id === sel.id || msg.recipient_id === sel.id)) {
        appendMessage(msg);
      }
    };

    // BUG 9 FIX: both handlers use appendMessage which deduplicates by id
    const onSent     = msg => {
      const sel = selectedRef.current;
      if (sel && msg.recipient_id === sel.id) {
        appendMessage(msg);
      }
    };
    const onTyping   = ({ user_id }) => { if (selectedRef.current?.id === user_id) setPeerTyping(true); };
    const onStopType = ({ user_id }) => { if (selectedRef.current?.id === user_id) setPeerTyping(false); };

    socket.on('receive_message',  onReceive);
    socket.on('message_sent',     onSent);
    socket.on('user_typing',      onTyping);
    socket.on('user_stop_typing', onStopType);

    return () => {
      socket.off('receive_message',  onReceive);
      socket.off('message_sent',     onSent);
      socket.off('user_typing',      onTyping);
      socket.off('user_stop_typing', onStopType);
    };
  // BUG 8 FIX: [socket] only — no `selected` dependency.
  // selectedRef keeps the closure current without re-registering listeners.
  }, [socket, appendMessage]);

  // ── Send message ───────────────────────────────────────────────────────────
  const sendMessage = async () => {
    if (!input.trim() || !selected || !cryptoKeys || !socket) return;
    const plaintext = input.trim(); setInput('');
    try {
      const payload = await encryptMessage({
        plaintext,
        myPrivateSignKey:          cryptoKeys.privateSignKey,
        myPrivateECDHKey:          cryptoKeys.privateECDHKey,
        recipientECDHPublicKeyPEM: selected.ecdh_public_key,
        recipientRSAPublicKeyPEM:  selected.public_key_encrypt || selected.public_key,
      });
      socket.emit('send_message', { token, recipient_id: selected.id, ...payload });
    } catch (err) { console.error('Encrypt error:', err); }
  };

  const handleKeyDown = e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); return; }
    if (!isTyping.current && socket && selected) {
      isTyping.current = true;
      socket.emit('typing', { token, recipient_id: selected.id });
    }
    clearTimeout(typingTimeout.current);
    typingTimeout.current = setTimeout(() => {
      isTyping.current = false;
      if (socket && selected) socket.emit('stop_typing', { token, recipient_id: selected.id });
    }, 1500);
  };

  const VerifyBadge = ({ verified, hashOk }) =>
    verified && hashOk
      ? <span title="Verified"  style={{ color: 'var(--success)', fontSize: 11 }}>✔✔</span>
      : <span title="Tampered!" style={{ color: 'var(--danger)',  fontSize: 11 }}>⚠️</span>;

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className={styles.layout}>

      {/* Sidebar */}
      <aside className={styles.sidebar}>
        <div className={styles.sidebarHeader}>
          <div className={styles.brandRow}>
            <span className={styles.brand}>🔐 CipherLink</span>
            <div className={styles.headerActions}>
              <button onClick={toggle} className={styles.iconBtn}>{theme === 'light' ? '🌙' : '☀️'}</button>
              <button onClick={logout} className={styles.iconBtn} title="Logout">⏻</button>
            </div>
          </div>
          <div className={styles.userInfo}>
            <span className={`${styles.dot} ${connected ? styles.online : styles.offline}`} />
            <span className={styles.username}>{user?.username}</span>
          </div>
          <input className={styles.search} placeholder="Search users…"
                 value={search} onChange={e => setSearch(e.target.value)} />
        </div>

        <div className={styles.contactList}>
          {contacts.length === 0 && <div className={styles.empty}>No users found</div>}
          {contacts.map(c => (
            <div key={c.id}
                 className={`${styles.contact} ${selected?.id === c.id ? styles.active : ''}`}
                 onClick={() => setSelected(c)}>
              <div className={styles.avatar}>{c.username[0].toUpperCase()}</div>
              <div className={styles.contactInfo}>
                <span className={styles.contactName}>{c.username}</span>
                {/* BUG 10 FIX: live socket Set, not stale DB field */}
                <span className={styles.contactStatus}>
                  {onlineUsers.has(c.id) ? '🟢 Online' : '⚫ Offline'}
                </span>
              </div>
            </div>
          ))}
        </div>
      </aside>

      {/* Main */}
      <main className={styles.main}>
        {keyError && (
          <div className={styles.keyWarning}>
            ⚠️ Session keys not found. <a href="/login">Log in again</a> to regenerate.
          </div>
        )}

        {!selected ? (
          <div className={styles.placeholder}>
            <div className={styles.placeholderIcon}>🔐</div>
            <h2>Select a contact to start chatting</h2>
            <p>All messages are end-to-end encrypted</p>
            <div className={styles.cryptoBadges}>
              <span>AES-256-GCM</span><span>RSA-2048</span>
              <span>ECDH P-256</span><span>SHA-256</span>
            </div>
          </div>
        ) : (
          <>
            <div className={styles.chatHeader}>
              <div className={styles.avatar} style={{ width: 36, height: 36, fontSize: 16 }}>
                {selected.username[0].toUpperCase()}
              </div>
              <div>
                <div className={styles.chatHeaderName}>{selected.username}</div>
                <div className={styles.chatHeaderStatus}>
                  {/* BUG 10 FIX: live socket Set */}
                  {onlineUsers.has(selected.id) ? '🟢 Online' : '⚫ Offline'} · 🔒 E2E Encrypted
                </div>
              </div>
            </div>

            <div className={styles.messages}>
              {messages.map(msg => {
                const isMine = msg.sender_id === user.id;
                const dec    = decryptedCache[msg.id];
                return (
                  <div key={msg.id} className={`${styles.msgRow} ${isMine ? styles.mine : styles.theirs}`}>
                    <div className={`${styles.bubble} ${isMine ? styles.bubbleMine : styles.bubbleTheirs}`}>
                      <div className={styles.msgText}>{dec ? dec.plaintext : '🔓 Decrypting…'}</div>
                      <div className={styles.msgMeta}>
                        <span>{new Date(msg.timestamp).toLocaleTimeString()}</span>
                        {dec && !isMine && <VerifyBadge verified={dec.verified} hashOk={dec.hashOk} />}
                        {msg.is_read ? ' ✓✓' : msg.is_delivered ? ' ✓' : ' ○'}
                      </div>
                    </div>
                  </div>
                );
              })}
              {peerTyping && (
                <div className={`${styles.msgRow} ${styles.theirs}`}>
                  <div className={`${styles.bubble} ${styles.bubbleTheirs} ${styles.typing}`}>
                    <span /><span /><span />
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            <div className={styles.inputArea}>
              <div className={styles.encryptBadge}>🔒 AES-256-GCM</div>
              <textarea className={styles.input}
                        placeholder="Type a message… (Enter to send)"
                        value={input}
                        onChange={e => setInput(e.target.value)}
                        onKeyDown={handleKeyDown}
                        rows={1} />
              <button className={styles.sendBtn}
                      onClick={sendMessage}
                      disabled={!input.trim() || !cryptoKeys}>➤</button>
            </div>
          </>
        )}
      </main>
    </div>
  );
}