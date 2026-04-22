"""
User document helpers — wraps MongoDB 'users' collection.

Schema:
  _id             ObjectId  (auto)
  username        str       unique, indexed
  email           str       unique
  password_hash   str       bcrypt
  public_key      str       RSA-PSS PEM  (stored for signature verification)
  public_key_encrypt str    RSA-OAEP PEM (stored for AES key wrapping)
  ecdh_public_key str       ECDH P-256 PEM
  is_online       bool
  last_seen       datetime
  created_at      datetime
"""
import re
from datetime import datetime
from bson import ObjectId
from models.database import get_db


def _col():
    return get_db().users


def user_to_dict(doc) -> dict:
    if doc is None:
        return None
    return {
        'id':              str(doc['_id']),
        'username':        doc.get('username', ''),
        'email':           doc.get('email', ''),
        'public_key':      doc.get('public_key', ''),
        'public_key_encrypt': doc.get('public_key_encrypt', ''),
        'ecdh_public_key': doc.get('ecdh_public_key', ''),
        'is_online':       doc.get('is_online', False),
        'last_seen':       doc['last_seen'].isoformat() if doc.get('last_seen') else None,
        'created_at':      doc['created_at'].isoformat() if doc.get('created_at') else None,
    }


def find_by_id(user_id: str):
    try:
        return _col().find_one({'_id': ObjectId(user_id)})
    except Exception:
        return None


def find_by_username(username: str):
    return _col().find_one({'username': username})


def find_by_email(email: str):
    return _col().find_one({'email': email})


def create_user(username, email, password_hash, public_key='', ecdh_public_key='', public_key_encrypt=''):
    now = datetime.utcnow()
    doc = {
        'username':        username,
        'email':           email,
        'password_hash':   password_hash,
        'public_key':      public_key,
        'public_key_encrypt': public_key_encrypt,
        'ecdh_public_key': ecdh_public_key,
        'is_online':       False,
        'last_seen':       now,
        'created_at':      now,
    }
    result  = _col().insert_one(doc)
    doc['_id'] = result.inserted_id
    return doc


def set_online(user_id: str, online: bool):
    _col().update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'is_online': online, 'last_seen': datetime.utcnow()}}
    )


def update_keys(user_id: str, public_key=None, ecdh_public_key=None):
    updates = {}
    if public_key      is not None: updates['public_key']      = public_key
    if ecdh_public_key is not None: updates['ecdh_public_key'] = ecdh_public_key
    if updates:
        _col().update_one({'_id': ObjectId(user_id)}, {'$set': updates})


def search_users(exclude_id: str, search: str = '', limit: int = 50):
    query = {'_id': {'$ne': ObjectId(exclude_id)}}
    if search:
        query['username'] = {'$regex': re.escape(search), '$options': 'i'}
    return list(_col().find(query).sort('username', 1).limit(limit))
