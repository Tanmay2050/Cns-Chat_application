/**
 * frontend/src/context/SocketContext.js  —  FIXED
 * =================================================
 *
 * BUGS FOUND AND FIXED
 * --------------------
 *
 * BUG 5 (CRITICAL) — socket is always null on first render
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * Original code:
 *   const socketRef = useRef(null);
 *   ...
 *   socketRef.current = socket;            // written inside useEffect
 *   ...
 *   value={{ socket: socketRef.current }}  // read during the SAME render
 *
 * useEffect runs AFTER the render, not during it. React reads
 * socketRef.current when it evaluates the Provider JSX — which happens
 * before the effect runs — so every consumer always receives null.
 *
 * ChatPage's socket useEffect has `if (!socket) return` as its first line.
 * Because socket is always null on the initial render and a ref mutation
 * does NOT trigger a re-render, ChatPage never attaches its listeners.
 * Ayush (who opened the app second) is the victim here: Vedant's tab may
 * have attached listeners during a lucky re-render caused by something else,
 * but Ayush's tab never gets that chance.
 *
 * Fix: store the socket instance in useState instead of useRef.
 *   setSocket(s) triggers a Provider re-render → all consumers get the real
 *   socket object → ChatPage's useEffect runs and registers listeners.
 *
 * BUG 6 (MAJOR) — onlineUsers never seeded for already-connected peers
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * user_online is only broadcast at the moment a user connects.
 * If Vedant is already online when Ayush loads the app, Ayush will never
 * receive Vedant's user_online event and will see him as offline forever —
 * exactly the asymmetric symptom you described.
 *
 * Fix: the fixed backend now emits 'online_users_snapshot' immediately
 * after connect. This context listens for it and seeds the entire Set.
 *
 * BUG 7 (MODERATE) — reconnection leaves ghost online entries
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * On reconnect, socket.io fires 'connect' again, but onlineUsers in React
 * state is never cleared. Stale user IDs accumulate across reconnections.
 *
 * Fix: clear onlineUsers on every (re)connect; the snapshot re-seeds it.
 */

import React, { createContext, useContext, useEffect, useState } from 'react';
import { io } from 'socket.io-client';
import { useAuth } from './AuthContext';

const SocketContext = createContext();

export function SocketProvider({ children }) {
  const { token } = useAuth();

  // BUG 5 FIX: useState so consumers re-render when socket becomes available
  const [socket,      setSocket]      = useState(null);
  const [connected,   setConnected]   = useState(false);
  const [onlineUsers, setOnlineUsers] = useState(new Set());

  useEffect(() => {
    if (!token) return;

    const s = io('http://localhost:5000', {
      auth:                 { token },
      transports:           ['websocket'],
      reconnection:         true,
      reconnectionDelay:    1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: Infinity,
    });

    // BUG 5 FIX: triggers re-render so children see the real socket
    setSocket(s);

    // BUG 7 FIX: clear stale presence on every (re)connect
    s.on('connect', () => {
      setConnected(true);
      setOnlineUsers(new Set());  // snapshot arriving right after will re-seed this
    });

    s.on('disconnect', () => setConnected(false));

    // BUG 6 FIX: seed the full online list from the snapshot the backend sends
    s.on('online_users_snapshot', ({ user_ids }) => {
      setOnlineUsers(new Set(user_ids));
    });

    s.on('user_online',  ({ user_id }) =>
      setOnlineUsers(prev => new Set([...prev, user_id])));

    s.on('user_offline', ({ user_id }) =>
      setOnlineUsers(prev => { const n = new Set(prev); n.delete(user_id); return n; }));

    return () => {
      s.disconnect();
      setSocket(null);
      setConnected(false);
      setOnlineUsers(new Set());
    };
  }, [token]);

  return (
    <SocketContext.Provider value={{ socket, connected, onlineUsers }}>
      {children}
    </SocketContext.Provider>
  );
}

export const useSocket = () => useContext(SocketContext);