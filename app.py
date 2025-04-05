from flask import Flask, request, render_template, send_file, jsonify
import secrets
import io
import time
from datetime import datetime, timedelta
import os

app = Flask(__name__)

# In-memory storage for files
# Structure: {otp: {'file': file_data, 'filename': filename, 'expiry': expiry_time}}
file_storage = {}

def generate_otp():
    return secrets.token_hex(3)  # Generates a 6-character hex string

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
    
    # Store file in memory
    file_data = io.BytesIO(file.read())
    file_storage[otp] = {
        'file': file_data,
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
    
    # Get the file and delete it from storage
    file_data = file_storage[otp]['file']
    filename = file_storage[otp]['filename']
    del file_storage[otp]
    
    # Reset file pointer to beginning
    file_data.seek(0)
    return send_file(
        file_data,
        download_name=filename,
        as_attachment=True
    )

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