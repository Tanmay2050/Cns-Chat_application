import uuid
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.message import (
    nonce_exists, create_message, get_conversation,
    mark_delivered, msg_to_dict
)
from models.user import find_by_id

messages_bp = Blueprint('messages', __name__)


@messages_bp.route('/messages/<contact_id>', methods=['GET'])
@jwt_required()
def get_messages(contact_id):
    current_id = get_jwt_identity()
    page       = request.args.get('page', 1, type=int)

    if not find_by_id(contact_id):
        return jsonify({'error': 'Contact not found'}), 404

    docs, total, pages = get_conversation(current_id, contact_id, page=page, per_page=50)
    mark_delivered(user_id=current_id, contact_id=contact_id)

    return jsonify({
        'messages':     [msg_to_dict(d) for d in docs],
        'total':        total,
        'pages':        pages,
        'current_page': page,
    })


@messages_bp.route('/messages', methods=['POST'])
@jwt_required()
def store_message():
    current_id   = get_jwt_identity()
    data         = request.get_json() or {}
    recipient_id = data.get('recipient_id')

    if not recipient_id or recipient_id == current_id:
        return jsonify({'error': 'Invalid recipient'}), 400
    if not find_by_id(recipient_id):
        return jsonify({'error': 'Recipient not found'}), 404

    nonce = data.get('nonce') or str(uuid.uuid4())
    if nonce_exists(nonce):
        return jsonify({'error': 'Duplicate message (replay detected)'}), 409

    msg = create_message(
        sender_id         = current_id,
        recipient_id      = recipient_id,
        encrypted_content = data.get('encrypted_content', ''),
        encrypted_aes_key = data.get('encrypted_aes_key', ''),
        message_hash      = data.get('message_hash', ''),
        signature         = data.get('signature', ''),
        nonce             = nonce,
    )
    return jsonify({'message': 'Stored', 'id': str(msg['_id'])}), 201
