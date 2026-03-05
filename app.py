import os
import json
import time
import shutil
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, url_for
from werkzeug.utils import secure_filename
from flask_cors import CORS
import uuid

app = Flask(__name__)
CORS(app)

# Configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 
                                    'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar', '7z', 'mp3', 
                                    'mp4', 'avi', 'mov', 'mkv', 'js', 'html', 'css', 'py', 
                                    'java', 'cpp', 'json', 'csv'}

# File to store shared files metadata
SHARED_FILES_DB = 'shared_files.json'

# Create uploads folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def load_shared_files():
    """Load shared files metadata from JSON file"""
    if os.path.exists(SHARED_FILES_DB):
        try:
            with open(SHARED_FILES_DB, 'r') as f:
                return json.load(f)
        except:
            return []
    return []

def save_shared_files(files_data):
    """Save shared files metadata to JSON file"""
    with open(SHARED_FILES_DB, 'w') as f:
        json.dump(files_data, f, indent=2)

def format_file_size(bytes):
    """Format file size for display"""
    if bytes == 0:
        return '0 B'
    k = 1024
    sizes = ['B', 'KB', 'MB', 'GB']
    i = int(math.floor(math.log(bytes) / math.log(k)))
    return f"{round(bytes / (k ** i), 1)} {sizes[i]}"

@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/api/files', methods=['GET'])
def get_files():
    """Get all shared files"""
    files = load_shared_files()
    # Sort by upload date (newest first)
    files.sort(key=lambda x: x['uploaded_at'], reverse=True)
    return jsonify(files)

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload a new file"""
    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400
    
    files = request.files.getlist('files')
    uploaded_files = []
    
    for file in files:
        if file and file.filename and allowed_file(file.filename):
            # Generate unique filename
            original_filename = secure_filename(file.filename)
            filename_parts = os.path.splitext(original_filename)
            unique_id = str(uuid.uuid4())[:8]
            unique_filename = f"{filename_parts[0]}_{unique_id}{filename_parts[1]}"
            
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            
            # Get file size
            file_size = os.path.getsize(file_path)
            
            # Create file metadata
            file_data = {
                'id': str(uuid.uuid4()),
                'original_name': original_filename,
                'stored_name': unique_filename,
                'size': file_size,
                'size_formatted': format_file_size(file_size),
                'uploaded_at': time.time(),
                'date': 'just now',
                'download_url': url_for('download_file', file_id=unique_filename, _external=True)
            }
            
            uploaded_files.append(file_data)
    
    if uploaded_files:
        # Load existing files and add new ones
        existing_files = load_shared_files()
        existing_files.extend(uploaded_files)
        save_shared_files(existing_files)
        
        return jsonify({
            'success': True,
            'files': uploaded_files,
            'message': f'Successfully uploaded {len(uploaded_files)} file(s)'
        })
    else:
        return jsonify({'error': 'No valid files uploaded'}), 400

@app.route('/api/download/<file_id>')
def download_file(file_id):
    """Download a file"""
    files = load_shared_files()
    
    # Find the file
    file_info = next((f for f in files if f['stored_name'] == file_id), None)
    
    if not file_info:
        return jsonify({'error': 'File not found'}), 404
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
    
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found on server'}), 404
    
    return send_file(
        file_path,
        as_attachment=True,
        download_name=file_info['original_name']
    )

@app.route('/api/delete/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete a file"""
    files = load_shared_files()
    
    # Find and remove the file
    file_to_delete = next((f for f in files if f['id'] == file_id), None)
    
    if not file_to_delete:
        return jsonify({'error': 'File not found'}), 404
    
    # Remove from files list
    files = [f for f in files if f['id'] != file_id]
    
    # Delete physical file
    stored_name = file_to_delete['stored_name']
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)
    
    if os.path.exists(file_path):
        os.remove(file_path)
    
    # Update database
    save_shared_files(files)
    
    return jsonify({'success': True, 'message': 'File deleted successfully'})

@app.route('/api/share/<file_id>', methods=['POST'])
def share_file(file_id):
    """Generate shareable link for a file"""
    files = load_shared_files()
    
    file_info = next((f for f in files if f['id'] == file_id), None)
    
    if not file_info:
        return jsonify({'error': 'File not found'}), 404
    
    # Generate shareable link (could implement expiration, password protection, etc.)
    share_link = url_for('download_file', file_id=file_info['stored_name'], _external=True)
    
    return jsonify({
        'success': True,
        'share_link': share_link,
        'message': 'Share link generated successfully'
    })

@app.route('/api/clear', methods=['POST'])
def clear_all_files():
    """Clear all files (admin function)"""
    # Delete all files in uploads folder
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print(f'Failed to delete {file_path}. Reason: {e}')
    
    # Clear database
    save_shared_files([])
    
    return jsonify({'success': True, 'message': 'All files cleared'})

if __name__ == '__main__':
    import math  # Import here for format_file_size function
    app.run(debug=True, host='0.0.0.0', port=5000)