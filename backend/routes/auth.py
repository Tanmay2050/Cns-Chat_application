import re
from flask import Blueprint, request, jsonify, make_response
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from models.user import (
    find_by_username, find_by_email, find_by_id,
    create_user, user_to_dict
)

auth_bp = Blueprint('auth', __name__)
bcrypt  = Bcrypt()


def valid_email(email: str) -> bool:
    return bool(re.match(r'^[^@]+@[^@]+\.[^@]+$', email))


@auth_bp.route('/register', methods=['POST'])
def register():
    data            = request.get_json() or {}
    username        = (data.get('username') or '').strip()
    email           = (data.get('email')    or '').strip()
    password        = data.get('password')        or ''
    public_key      = data.get('public_key')      or ''
    public_key_encrypt = data.get('public_key_encrypt') or ''
    ecdh_public_key = data.get('ecdh_public_key') or ''

    if not username or len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    if not valid_email(email):
        return jsonify({'error': 'Invalid email address'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if find_by_username(username):
        return jsonify({'error': 'Username already taken'}), 409
    if find_by_email(email):
        return jsonify({'error': 'Email already registered'}), 409

    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    user    = create_user(username, email, pw_hash, public_key, ecdh_public_key, public_key_encrypt)
    token   = create_access_token(identity=str(user['_id']))
    return jsonify({'message': 'Registered successfully', 'token': token,
                    'user': user_to_dict(user)}), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    data     = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    user = find_by_username(username)
    if not user or not bcrypt.check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = create_access_token(identity=str(user['_id']))
    resp  = make_response(jsonify({'message': 'Logged in', 'token': token,
                                   'user': user_to_dict(user)}))
    resp.set_cookie('access_token_cookie', token, httponly=True, samesite='Lax')
    return resp


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    resp = make_response(jsonify({'message': 'Logged out'}))
    resp.delete_cookie('access_token_cookie')
    return resp


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def me():
    user = find_by_id(get_jwt_identity())
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(user_to_dict(user))
