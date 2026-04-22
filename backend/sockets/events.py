"""
backend/sockets/events.py  — FIXED
===================================

BUGS FOUND AND FIXED
--------------------

BUG 1 (CRITICAL) — on_disconnect marks the WRONG user offline
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Original code:
    for uid in list(connected_users.keys()):
        set_online(uid, False)
        ...
        break           # <-- always takes the FIRST key in the dict

Python dicts preserve insertion order. "break" on the first loop
iteration means this ALWAYS marks whichever user connected first
as offline, regardless of who actually disconnected.

Scenario that produces your exact symptom:
  1. Vedant connects → connected_users = {'vedant_id': True}
  2. Ayush connects  → connected_users = {'vedant_id': True, 'ayush_id': True}
  3. Ayush closes/reopens tab → disconnect fires
  4. on_disconnect iterates → first key is 'vedant_id' → Vedant goes offline
  5. Result: Vedant appears offline to Ayush, online to himself ← exactly what you see

Fix: add a second dict  sid_to_user: {socket_id → user_id}
     and read flask_request.sid in on_disconnect to identify exactly
     which socket (and therefore which user) is leaving.

BUG 2 (MAJOR) — Redundant 'authenticate' event causes double room-join
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The frontend never emits a separate 'authenticate' event — it passes
auth={token} in the io() constructor, which on_connect already handles.
The handler is dead code, but if anything ever triggers it (reconnect
edge cases, manual testing) it calls join_room again and broadcasts a
second user_online event, corrupting the presence state.

Fix: remove the handler entirely.

BUG 3 (MAJOR) — Multi-tab: closing any tab marks user offline
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
connected_users stores uid → True (one flag per user). When any of a
user's tabs disconnects, the flag is removed immediately even if they
still have other tabs open, broadcasting a spurious user_offline.

Fix: store uid → set(sids). Only mark offline when the set is empty.

BUG 4 (MODERATE) — Late joiners never see who is already online
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
user_online is broadcast at the instant of connect. A user who joins
AFTER someone else is already connected will never receive that
historical event and will permanently see them as Offline.

Fix: emit 'online_users_snapshot' back to only the new socket,
carrying all currently connected user IDs. The frontend uses this
to seed onlineUsers on mount.
"""

import uuid
from flask import request as flask_request
from flask_socketio import SocketIO, emit, join_room, disconnect
from flask_jwt_extended import decode_token
from models.user import find_by_id, set_online
from models.message import (
    nonce_exists, create_message, msg_to_dict, mark_read_by_id, get_sender_id
)

# ── Presence tracking ──────────────────────────────────────────────────────────
#
# BEFORE (broken):
#   connected_users: dict[uid, bool]
#   - one entry per user no matter how many tabs they have open
#   - on_disconnect iterates and breaks on the first key (always wrong user)
#
# AFTER (fixed):
#   connected_users: dict[uid, set[sid]]   all active socket IDs per user
#   sid_to_user:     dict[sid, uid]        O(1) reverse lookup for disconnect

connected_users: dict = {}   # uid  → {sid, sid, …}
sid_to_user:     dict = {}   # sid  → uid


def _user_from_token(token: str):
    try:
        decoded = decode_token(token)
        return find_by_id(decoded['sub'])
    except Exception:
        return None


def register_socket_events(socketio: SocketIO):

    # ── connect ────────────────────────────────────────────────────────────────
    @socketio.on('connect')
    def on_connect(auth):
        token = (auth or {}).get('token')
        user  = _user_from_token(token) if token else None
        if not user:
            disconnect()
            return

        uid = str(user['_id'])
        sid = flask_request.sid                    # this socket's unique ID
        print(f"[DEBUG] User connected: {user['username']} ({uid}) on sid {sid}")

        # BUG 1 + BUG 3 FIX: register sid→uid and uid→{sids}
        sid_to_user[sid] = uid
        connected_users.setdefault(uid, set()).add(sid)

        join_room(f'user_{uid}')
        set_online(uid, True)

        # Confirm to this socket
        emit('connected', {'user_id': uid})

        # BUG 4 FIX: send the full current online list to the newcomer only
        # so late-joiners immediately see who is already connected
        emit('online_users_snapshot', {'user_ids': list(connected_users.keys())})

        # Tell everyone else this user came online
        emit('user_online', {'user_id': uid, 'username': user['username']},
             broadcast=True, include_self=False)

    # ── disconnect ─────────────────────────────────────────────────────────────
    @socketio.on('disconnect')
    def on_disconnect():
        sid = flask_request.sid                    # identify THIS socket

        # BUG 1 FIX: look up by sid, not by iterating the whole dict
        uid = sid_to_user.pop(sid, None)
        if uid is None:
            return   # connection was rejected at auth time; nothing to clean up

        # BUG 3 FIX: only go offline when ALL tabs/windows are closed
        sids = connected_users.get(uid, set())
        sids.discard(sid)
        if sids:
            return   # user still connected on another socket; stay online

        # Last socket gone — mark truly offline
        connected_users.pop(uid, None)
        set_online(uid, False)

        user = find_by_id(uid)
        if user:
            emit('user_offline', {'user_id': uid, 'username': user['username']},
                 broadcast=True)

    # BUG 2 FIX: 'authenticate' handler removed.
    # Auth is fully handled in on_connect via auth={token:…}.
    # The separate handler was never called by the frontend and caused
    # double join_room + duplicate user_online broadcast when it did fire.

    # ── send_message ───────────────────────────────────────────────────────────
    @socketio.on('send_message')
    def on_send_message(data):
        print(f"[DEBUG] send_message received: {data.get('recipient_id')}")
        data = data or {}
        user = _user_from_token(data.get('token'))
        if not user:
            print("[DEBUG] Unauthorized user in send_message")
            emit('error', {'message': 'Unauthorized'})
            return

        uid          = str(user['_id'])
        recipient_id = data.get('recipient_id')
        if not recipient_id or recipient_id == uid:
            emit('error', {'message': 'Invalid recipient'})
            return

        nonce = data.get('nonce') or str(uuid.uuid4())
        if nonce_exists(nonce):
            emit('error', {'message': 'Replay attack detected'})
            return

        msg = create_message(
            sender_id         = uid,
            recipient_id      = recipient_id,
            encrypted_content = data.get('encrypted_content', ''),
            encrypted_aes_key = data.get('encrypted_aes_key', ''),
            message_hash      = data.get('message_hash', ''),
            signature         = data.get('signature', ''),
            nonce             = nonce,
        )
        payload = msg_to_dict(msg)
        payload['sender_username'] = user['username']

        print(f"[DEBUG] Broadcasting receive_message to user_{recipient_id}")
        # Deliver to recipient
        emit('receive_message', payload, room=f'user_{recipient_id}')
        
        print(f"[DEBUG] Emitting message_sent to sender {user['username']}")
        # Confirm to sender
        emit('message_sent', payload)

    # ── typing indicators ──────────────────────────────────────────────────────
    @socketio.on('typing')
    def on_typing(data):
        data = data or {}
        user = _user_from_token(data.get('token'))
        if not user:
            return
        emit('user_typing',
             {'user_id': str(user['_id']), 'username': user['username']},
             room=f'user_{data.get("recipient_id")}')

    @socketio.on('stop_typing')
    def on_stop_typing(data):
        data = data or {}
        user = _user_from_token(data.get('token'))
        if not user:
            return
        emit('user_stop_typing', {'user_id': str(user['_id'])},
             room=f'user_{data.get("recipient_id")}')

    # ── mark read ──────────────────────────────────────────────────────────────
    @socketio.on('mark_read')
    def on_mark_read(data):
        data = data or {}
        user = _user_from_token(data.get('token'))
        if not user:
            return
        uid        = str(user['_id'])
        message_id = data.get('message_id', '')
        if mark_read_by_id(message_id, recipient_id=uid):
            sender_id = get_sender_id(message_id)
            if sender_id:
                emit('message_read', {'message_id': message_id},
                     room=f'user_{sender_id}')