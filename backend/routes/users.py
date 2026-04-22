from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.user import find_by_id, update_keys, search_users, user_to_dict

users_bp = Blueprint('users', __name__)


@users_bp.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    current_id = get_jwt_identity()
    search     = request.args.get('search', '').strip()
    users      = search_users(exclude_id=current_id, search=search, limit=50)
    return jsonify([user_to_dict(u) for u in users])


@users_bp.route('/users/<user_id>/public-key', methods=['GET'])
@jwt_required()
def get_public_key(user_id):
    user = find_by_id(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({
        'user_id':         str(user['_id']),
        'username':        user['username'],
        'public_key':      user.get('public_key', ''),
        'ecdh_public_key': user.get('ecdh_public_key', ''),
    })


@users_bp.route('/users/<user_id>/keys', methods=['PUT'])
@jwt_required()
def update_user_keys(user_id):
    if get_jwt_identity() != user_id:
        return jsonify({'error': 'Forbidden'}), 403
    if not find_by_id(user_id):
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json() or {}
    update_keys(user_id,
                public_key      = data.get('public_key'),
                ecdh_public_key = data.get('ecdh_public_key'))
    return jsonify({'message': 'Keys updated'})
