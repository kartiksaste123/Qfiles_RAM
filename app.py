from flask import Flask, request, render_template, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
import secrets
from datetime import datetime, timedelta
import threading
import os
import eventlet

eventlet.monkey_patch()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', ping_interval=25, ping_timeout=60)

# In-memory store of file metadata
file_metadata = {}

def generate_otp():
    return secrets.token_hex(3)  # 6-char hex string

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create-share', methods=['POST'])
def create_share():
    data = request.json
    if not data or 'filename' not in data or 'size' not in data or 'type' not in data:
        return jsonify({'error': 'Missing file information'}), 400

    otp = generate_otp()
    file_metadata[otp] = {
        'filename': data['filename'],
        'size': data['size'],
        'type': data['type'],
        'expiry': datetime.now() + timedelta(hours=24)
    }

    return jsonify({'otp': otp})

@app.route('/verify', methods=['POST'])
def verify_otp():
    otp = request.json.get('otp')
    if not otp or otp not in file_metadata:
        return jsonify({'error': 'Invalid OTP'}), 400

    metadata = file_metadata[otp]
    if datetime.now() > metadata['expiry']:
        del file_metadata[otp]
        return jsonify({'error': 'Share has expired'}), 400

    return jsonify({
        'filename': metadata['filename'],
        'size': metadata['size'],
        'type': metadata['type']
    })

@socketio.on('connect')
def handle_connect():
    print("[SOCKET] Client connected")

@socketio.on('disconnect')
def handle_disconnect():
    print("[SOCKET] Client disconnected")

@socketio.on('join')
def on_join(data):
    otp = data.get('otp')
    if otp in file_metadata:
        join_room(otp)
        emit('ready', {'otp': otp}, room=otp)
        print(f"[SOCKET] Client joined room: {otp}")

@socketio.on('offer')
def on_offer(data):
    otp = data.get('otp')
    if otp in file_metadata:
        emit('offer', data, room=otp)
        print(f"[SOCKET] Offer sent for OTP: {otp}")

@socketio.on('answer')
def on_answer(data):
    otp = data.get('otp')
    if otp in file_metadata:
        emit('answer', data, room=otp)
        print(f"[SOCKET] Answer sent for OTP: {otp}")

@socketio.on('ice-candidate')
def on_ice_candidate(data):
    otp = data.get('otp')
    if otp in file_metadata:
        emit('ice-candidate', data, room=otp)
        print(f"[SOCKET] ICE candidate sent for OTP: {otp}")

def cleanup_expired_shares():
    while True:
        current_time = datetime.now()
        expired_otps = [otp for otp, info in file_metadata.items() if current_time > info['expiry']]
        for otp in expired_otps:
            del file_metadata[otp]
        socketio.sleep(60)

@socketio.on_error_default
def default_error_handler(e):
    print(f"[SOCKET] Error: {e}")

if __name__ == '__main__':
    socketio.start_background_task(cleanup_expired_shares)
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port)
