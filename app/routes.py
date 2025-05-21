import os
from flask import Blueprint, request, render_template, redirect, url_for, flash, send_file, current_app, abort, jsonify
from werkzeug.utils import secure_filename
from app.models import File, db
from app.utils import encrypt_file, decrypt_file, hash_password, verify_password
import base64
from datetime import datetime
import io

bp = Blueprint('routes', __name__)

@bp.route('/', methods=['GET'])
def index():
    """Main page with upload form"""
    return render_template('index.html')

@bp.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and encryption"""
    #check if file is in the request
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    
    # Check if file was selected
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Get upload parameters
    password = request.form.get('password', '')
    max_downloads = request.form.get('max_downloads', type=int)
    expire_days = request.form.get('expire_days', 7, type=int)
    
    # Check if file is allowed
    filename = secure_filename(file.filename)
    
    # Read and encrypt the file
    file_data = file.read()
    encryption_result = encrypt_file(file_data, password if password else 'default-key')
    
    # Generate unique filename
    encrypted_filename = f"{os.urandom(8).hex()}_{filename}"
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], encrypted_filename)
    

    with open(file_path, 'wb') as f:
        f.write(encryption_result['ciphertext'])
    

    password_protected = bool(password)
    password_hash = None
    salt_for_password = None
    
    if password_protected:
        password_hash, salt_for_password = hash_password(password)
    
    file_record = File.create_file(
        filename=filename,
        file_path=file_path,
        salt=encryption_result['salt'],
        iv=encryption_result['iv'],
        password_protected=password_protected,
        password_hash=password_hash,
        expire_days=expire_days,
        max_downloads=max_downloads
    )

    download_link = url_for('routes.download_page', file_id=file_record.id, 
                            access_key=file_record.access_key, _external=True)
    
    return jsonify({
        'success': True,
        'download_link': download_link
    })

@bp.route('/download/<file_id>', methods=['GET'])
def download_page(file_id):
    """Show download page for a file"""
    access_key = request.args.get('access_key')
    if not access_key:
        return abort(404)
    file_record = File.query.filter_by(id=file_id, access_key=access_key).first_or_404()
    
    #check if file has expired
    if file_record.is_expired:
        #Delete expired file
        if os.path.exists(file_record.file_path):
            os.remove(file_record.file_path)
        db.session.delete(file_record)
        db.session.commit()
        return render_template('download.html', error="File has expired or reached maximum downloads")
    
    return render_template('download.html', file=file_record)

@bp.route('/download/<file_id>/file', methods=['POST'])
def download_file(file_id):
    """Process file download with password verification"""
    access_key = request.args.get('access_key')
    if not access_key:
        return abort(404)
    
    #find file record
    file_record = File.query.filter_by(id=file_id, access_key=access_key).first_or_404()
    
    #check if file has expired
    if file_record.is_expired:
        return jsonify({'error': 'File has expired or reached maximum downloads'}), 400
    
    #verify password if needed
    if file_record.password_protected:
        password = request.form.get('password', '')
        if not verify_password(password, file_record.password_hash, 
                             base64.b64decode(file_record.password_hash)):
            return jsonify({'error': 'Invalid password'}), 401
    
    #read encrypted file
    with open(file_record.file_path, 'rb') as f:
        encrypted_data = f.read()

    password = request.form.get('password', 'default-key')
    try:
        decrypted_data = decrypt_file(
            encrypted_data, 
            password, 
            file_record.salt, 
            file_record.iv
        )
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 400
    file_record.download_count += 1
    
 
    if file_record.max_downloads and file_record.download_count >= file_record.max_downloads:
        if os.path.exists(file_record.file_path):
            os.remove(file_record.file_path)
        db.session.delete(file_record)
    
    db.session.commit()
    
    #DOWNLOAD FILE
    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=file_record.filename
    )
