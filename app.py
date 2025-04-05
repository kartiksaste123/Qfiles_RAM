from flask import Flask, request, render_template, send_file, jsonify
import secrets
import io
import time
from datetime import datetime, timedelta
import os
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)

# Generate a key for encryption (in production, this should be stored securely)
# You should generate this once and store it securely, not generate it on each restart
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
fernet = Fernet(ENCRYPTION_KEY)

# In-memory storage for files
# Structure: {otp: {'encrypted_file': encrypted_file_data, 'filename': filename, 'expiry': expiry_time}}
file_storage = {}

def generate_otp():
    return secrets.token_hex(3)  # Generates a 6-character hex string

def encrypt_file(file_data):
    """Encrypt file data using Fernet symmetric encryption"""
    return fernet.encrypt(file_data)

def decrypt_file(encrypted_data):
    """Decrypt file data using Fernet symmetric encryption"""
    return fernet.decrypt(encrypted_data)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Generate OTP
    otp = generate_otp()
    
    # Read and encrypt file data
    file_data = file.read()
    encrypted_data = encrypt_file(file_data)
    
    # Store encrypted file in memory
    file_storage[otp] = {
        'encrypted_file': encrypted_data,
        'filename': file.filename,
        'expiry': datetime.now() + timedelta(hours=24)  # Files expire after 24 hours
    }
    
    return jsonify({'otp': otp})

@app.route('/verify', methods=['POST'])
def verify_otp():
    otp = request.json.get('otp')
    if not otp or otp not in file_storage:
        return jsonify({'error': 'Invalid OTP'}), 400
    
    file_info = file_storage[otp]
    if datetime.now() > file_info['expiry']:
        del file_storage[otp]
        return jsonify({'error': 'File has expired'}), 400
    
    return jsonify({
        'filename': file_info['filename'],
        'download_url': f'/download/{otp}'
    })

@app.route('/download/<otp>')
def download_file(otp):
    if otp not in file_storage:
        return jsonify({'error': 'Invalid OTP'}), 400
    
    file_info = file_storage[otp]
    if datetime.now() > file_info['expiry']:
        del file_storage[otp]
        return jsonify({'error': 'File has expired'}), 400
    
    try:
        # Decrypt the file data
        decrypted_data = decrypt_file(file_info['encrypted_file'])
        
        # Create a BytesIO object with the decrypted data
        file_data = io.BytesIO(decrypted_data)
        filename = file_info['filename']
        
        # Delete the file from storage
        del file_storage[otp]
        
        # Reset file pointer to beginning
        file_data.seek(0)
        return send_file(
            file_data,
            download_name=filename,
            as_attachment=True
        )
    except Exception as e:
        return jsonify({'error': 'Error processing file'}), 500

# Cleanup expired files periodically
def cleanup_expired_files():
    current_time = datetime.now()
    expired_otps = [
        otp for otp, info in file_storage.items()
        if current_time > info['expiry']
    ]
    for otp in expired_otps:
        del file_storage[otp]

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port) 
