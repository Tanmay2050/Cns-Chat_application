"""
Message document helpers — wraps MongoDB 'messages' collection.

Schema:
  _id               ObjectId
  sender_id         str   (ObjectId as string)
  recipient_id      str
  encrypted_content str   base64(IV + AES-GCM ciphertext)
  encrypted_aes_key str   AES key wrapped with recipient RSA-OAEP public key
  message_hash      str   SHA-256 hex of plaintext
  signature         str   RSA-PSS base64 signature of message_hash
  nonce             str   unique random value (replay prevention)
  timestamp         datetime
  is_delivered      bool
  is_read           bool
  is_deleted        bool  soft-delete
"""
import math
from datetime import datetime
from bson import ObjectId
from models.database import get_db


def _col():
    return get_db().messages


def msg_to_dict(doc) -> dict:
    if doc is None:
        return None
    return {
        'id':                str(doc['_id']),
        'sender_id':         doc.get('sender_id', ''),
        'recipient_id':      doc.get('recipient_id', ''),
        'encrypted_content': doc.get('encrypted_content', ''),
        'encrypted_aes_key': doc.get('encrypted_aes_key', ''),
        'message_hash':      doc.get('message_hash', ''),
        'signature':         doc.get('signature', ''),
        'nonce':             doc.get('nonce', ''),
        'timestamp':         doc['timestamp'].isoformat() if doc.get('timestamp') else None,
        'is_delivered':      doc.get('is_delivered', False),
        'is_read':           doc.get('is_read', False),
    }


def nonce_exists(nonce: str) -> bool:
    return _col().find_one({'nonce': nonce}) is not None


def create_message(sender_id, recipient_id, encrypted_content, encrypted_aes_key,
                   message_hash, signature, nonce):
    doc = {
        'sender_id':         sender_id,
        'recipient_id':      recipient_id,
        'encrypted_content': encrypted_content,
        'encrypted_aes_key': encrypted_aes_key,
        'message_hash':      message_hash,
        'signature':         signature,
        'nonce':             nonce,
        'timestamp':         datetime.utcnow(),
        'is_delivered':      False,
        'is_read':           False,
        'is_deleted':        False,
    }
    result     = _col().insert_one(doc)
    doc['_id'] = result.inserted_id
    return doc


def get_conversation(user_id: str, contact_id: str, page: int = 1, per_page: int = 50):
    query = {
        'is_deleted': False,
        '$or': [
            {'sender_id': user_id,    'recipient_id': contact_id},
            {'sender_id': contact_id, 'recipient_id': user_id},
        ]
    }
    total = _col().count_documents(query)
    skip  = (page - 1) * per_page
    docs  = list(_col().find(query).sort('timestamp', 1).skip(skip).limit(per_page))
    pages = math.ceil(total / per_page) if total else 1
    return docs, total, pages


def mark_delivered(user_id: str, contact_id: str):
    _col().update_many(
        {'sender_id': contact_id, 'recipient_id': user_id, 'is_delivered': False},
        {'$set': {'is_delivered': True}}
    )


def mark_read_by_id(message_id: str, recipient_id: str) -> bool:
    result = _col().update_one(
        {'_id': ObjectId(message_id), 'recipient_id': recipient_id},
        {'$set': {'is_read': True}}
    )
    return result.modified_count > 0


def get_sender_id(message_id: str):
    doc = _col().find_one({'_id': ObjectId(message_id)}, {'sender_id': 1})
    return doc['sender_id'] if doc else None
