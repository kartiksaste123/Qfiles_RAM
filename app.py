from flask import Flask, request, render_template, jsonify, session
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
import secrets
from datetime import datetime, timedelta
import os
import logging
import eventlet

# Patch eventlet
eventlet.monkey_patch()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SESSION_TYPE'] = 'filesystem'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', logger=True, engineio_logger=True, ping_timeout=60, ping_interval=25)

# Store only OTP and metadata, not the actual file
# Structure: {otp: {'filename': filename, 'size': size, 'type': type, 'expiry': expiry_time}}
file_metadata = {}

def generate_otp():
    return secrets.token_hex(3)  # Generates a 6-character hex string

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create-share', methods=['POST'])
def create_share():
    try:
        data = request.json
        if not data or 'filename' not in data or 'size' not in data or 'type' not in data:
            return jsonify({'error': 'Missing file information'}), 400

        # Generate OTP
        otp = generate_otp()
        
        # Store only metadata
        file_metadata[otp] = {
            'filename': data['filename'],
            'size': data['size'],
            'type': data['type'],
            'expiry': datetime.now() + timedelta(hours=24)
        }
        
        logger.info(f"Share created with OTP: {otp}")
        return jsonify({'otp': otp})
    except Exception as e:
        logger.error(f"Error creating share: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/verify', methods=['POST'])
def verify_otp():
    try:
        otp = request.json.get('otp')
        if not otp or otp not in file_metadata:
            return jsonify({'error': 'Invalid OTP'}), 400
        
        metadata = file_metadata[otp]
        if datetime.now() > metadata['expiry']:
            del file_metadata[otp]
            return jsonify({'error': 'Share has expired'}), 400
        
        logger.info(f"OTP verified: {otp}")
        return jsonify({
            'filename': metadata['filename'],
            'size': metadata['size'],
            'type': metadata['type']
        })
    except Exception as e:
        logger.error(f"Error verifying OTP: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# WebSocket events for signaling
@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('join')
def on_join(data):
    try:
        otp = data.get('otp')
        if not otp:
            logger.error("No OTP provided for join")
            return
        
        if otp in file_metadata:
            join_room(otp)
            emit('ready', {'otp': otp}, room=otp)
            logger.info(f"Client {request.sid} joined room: {otp}")
        else:
            logger.warning(f"Invalid OTP for join: {otp}")
            emit('error', {'message': 'Invalid OTP'})
    except Exception as e:
        logger.error(f"Error in join: {str(e)}")
        emit('error', {'message': 'Internal server error'})

@socketio.on('offer')
def on_offer(data):
    try:
        otp = data.get('otp')
        if otp in file_metadata:
            emit('offer', data, room=otp)
            logger.info(f"Offer sent for OTP: {otp}")
        else:
            logger.warning(f"Invalid OTP for offer: {otp}")
            emit('error', {'message': 'Invalid OTP'})
    except Exception as e:
        logger.error(f"Error in offer: {str(e)}")
        emit('error', {'message': 'Internal server error'})

@socketio.on('answer')
def on_answer(data):
    try:
        otp = data.get('otp')
        if otp in file_metadata:
            emit('answer', data, room=otp)
            logger.info(f"Answer sent for OTP: {otp}")
        else:
            logger.warning(f"Invalid OTP for answer: {otp}")
            emit('error', {'message': 'Invalid OTP'})
    except Exception as e:
        logger.error(f"Error in answer: {str(e)}")
        emit('error', {'message': 'Internal server error'})

@socketio.on('ice-candidate')
def on_ice_candidate(data):
    try:
        otp = data.get('otp')
        if otp in file_metadata:
            emit('ice-candidate', data, room=otp)
            logger.info(f"ICE candidate sent for OTP: {otp}")
        else:
            logger.warning(f"Invalid OTP for ICE candidate: {otp}")
            emit('error', {'message': 'Invalid OTP'})
    except Exception as e:
        logger.error(f"Error in ice-candidate: {str(e)}")
        emit('error', {'message': 'Internal server error'})

# Cleanup expired shares periodically
def cleanup_expired_shares():
    try:
        current_time = datetime.now()
        expired_otps = [
            otp for otp, info in file_metadata.items()
            if current_time > info['expiry']
        ]
        for otp in expired_otps:
            del file_metadata[otp]
            logger.info(f"Cleaned up expired share: {otp}")
    except Exception as e:
        logger.error(f"Error in cleanup: {str(e)}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port) 
