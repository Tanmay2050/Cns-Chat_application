"""
MongoDB connection using PyMongo.
Call init_db(app) once at startup; then use get_db() anywhere.
"""
from pymongo import MongoClient, ASCENDING
from pymongo.errors import ConnectionFailure

_client = None
_db     = None


def init_db(app):
    global _client, _db
    mongo_uri = app.config.get('MONGO_URI', 'mongodb://localhost:27017/cipherlink')
    _client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)

    try:
        _client.admin.command('ping')
        print("✅ MongoDB connected.")
    except ConnectionFailure as exc:
        print(f"❌ MongoDB connection failed: {exc}")
        raise

    # Derive DB name from URI (last path segment, before any query string)
    db_name = mongo_uri.rsplit('/', 1)[-1].split('?')[0] or 'cipherlink'
    _db = _client[db_name]

    # ── Indexes ──
    _db.users.create_index([('username', ASCENDING)], unique=True)
    _db.users.create_index([('email',    ASCENDING)], unique=True)
    _db.messages.create_index([('nonce', ASCENDING)], unique=True)
    _db.messages.create_index([('sender_id', ASCENDING), ('recipient_id', ASCENDING)])
    _db.messages.create_index([('timestamp', ASCENDING)])
    print("✅ MongoDB indexes ready.")


def get_db():
    if _db is None:
        raise RuntimeError("Database not initialised. Call init_db(app) first.")
    return _db
