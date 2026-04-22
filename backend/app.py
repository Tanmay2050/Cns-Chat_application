import eventlet
eventlet.monkey_patch()

from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import os

from models.database import init_db
from routes.auth import auth_bp
from routes.users import users_bp
from routes.messages import messages_bp
from sockets.events import register_socket_events

load_dotenv()


def create_app():
    app = Flask(__name__)

    # ── Configuration ──
    app.config['SECRET_KEY']          = os.getenv('SECRET_KEY', 'dev-secret-key')
    app.config['JWT_SECRET_KEY']      = os.getenv('JWT_SECRET_KEY', 'dev-jwt-secret')
    app.config['MONGO_URI']           = os.getenv('MONGO_URI', 'mongodb://localhost:27017/cipherlink')
    app.config['JWT_TOKEN_LOCATION']  = ['headers', 'cookies']
    app.config['JWT_COOKIE_SECURE']   = False   # Set True in production (HTTPS)
    app.config['JWT_COOKIE_SAMESITE'] = 'Lax'
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600  # 1 hour

    # ── Extensions ──
    Bcrypt(app)
    JWTManager(app)
    Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
    CORS(app, supports_credentials=True, origins="*")

    socketio = SocketIO(
        app,
        cors_allowed_origins="*",
        async_mode='eventlet',
        logger=False,
        engineio_logger=False
    )

    # ── MongoDB ──
    init_db(app)

    # ── Blueprints ──
    app.register_blueprint(auth_bp,     url_prefix='/api')
    app.register_blueprint(users_bp,    url_prefix='/api')
    app.register_blueprint(messages_bp, url_prefix='/api')

    # ── Socket events ──
    register_socket_events(socketio)

    return app, socketio


if __name__ == '__main__':
    app, socketio = create_app()
    print("🚀 CipherLink backend starting on http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
