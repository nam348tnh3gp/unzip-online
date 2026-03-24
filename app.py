"""
Web Unzip Pro - Multi-User Edition
Supports concurrent users with isolated workspaces, Redis caching, rate limiting
"""

import os
import io
import zipfile
import tarfile
import tempfile
import shutil
import time
import json
import hashlib
import uuid
import threading
import logging
import traceback
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Optional, Tuple

# Flask and extensions
from flask import Flask, request, jsonify, send_file, render_template_string, session, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

# Background task queue
try:
    from celery import Celery
    HAS_CELERY = True
except ImportError:
    HAS_CELERY = False

# Redis for caching (optional)
try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

# Optional extended format support
try:
    import py7zr
    HAS_7Z = True
except ImportError:
    HAS_7Z = False

try:
    import rarfile
    HAS_RAR = True
except ImportError:
    HAS_RAR = False

# ==================== Configuration ====================
class Config:
    # Server config
    MAX_CONTENT_LENGTH = 1024 * 1024 * 1024  # 1GB
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24).hex())
    SESSION_TYPE = 'filesystem'  # Or 'redis'
    
    # Directories
    DATA_DIR = '/app/data' if os.environ.get('RENDER') else './data'
    UPLOAD_DIR = os.path.join(DATA_DIR, 'uploads')
    EXTRACT_DIR = os.path.join(DATA_DIR, 'extracts')
    TEMP_DIR = os.path.join(DATA_DIR, 'temp')
    
    # Performance
    MAX_WORKSPACE_SIZE = 1024 * 1024 * 1024  # 1GB per user
    MAX_CONCURRENT_EXTRACTIONS = 10
    EXTRACT_TIMEOUT = 300  # 5 minutes per file
    CLEANUP_INTERVAL = 3600  # 1 hour
    WORKSPACE_EXPIRY = 7200  # 2 hours idle
    
    # Rate limiting
    RATE_LIMIT = "30 per minute"
    RATE_LIMIT_STORAGE = "memory://"
    
    # Redis (optional)
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    
    # Celery (optional)
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/1')
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/2')
    
    # Allowed extensions
    ALLOWED_EXTENSIONS = {'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'tgz', 'tbz2'}

# Create directories
os.makedirs(Config.UPLOAD_DIR, exist_ok=True)
os.makedirs(Config.EXTRACT_DIR, exist_ok=True)
os.makedirs(Config.TEMP_DIR, exist_ok=True)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
CORS(app)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[Config.RATE_LIMIT],
    storage_uri=Config.RATE_LIMIT_STORAGE
)

# Redis client (optional)
redis_client = redis.from_url(Config.REDIS_URL) if HAS_REDIS else None

# Celery app (optional)
celery = None
if HAS_CELERY:
    celery = Celery(
        'unzip_tasks',
        broker=Config.CELERY_BROKER_URL,
        backend=Config.CELERY_RESULT_BACKEND
    )
    celery.conf.update(
        task_track_started=True,
        task_time_limit=Config.EXTRACT_TIMEOUT,
        task_soft_time_limit=Config.EXTRACT_TIMEOUT - 10,
    )

# ==================== Workspace Manager ====================

class WorkspaceManager:
    """Manage isolated workspaces for each user session"""
    
    def __init__(self):
        self._workspaces: Dict[str, dict] = {}
        self._lock = threading.Lock()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
    
    def create_workspace(self, session_id: str) -> dict:
        """Create a new workspace for a user"""
        workspace_id = hashlib.md5(f"{session_id}{time.time()}{uuid.uuid4()}".encode()).hexdigest()[:16]
        workspace_path = os.path.join(Config.EXTRACT_DIR, workspace_id)
        os.makedirs(workspace_path, exist_ok=True)
        
        workspace = {
            'id': workspace_id,
            'path': workspace_path,
            'session_id': session_id,
            'created_at': time.time(),
            'last_access': time.time(),
            'files': [],
            'total_size': 0,
            'active_extractions': 0
        }
        
        with self._lock:
            self._workspaces[workspace_id] = workspace
        
        return workspace
    
    def get_workspace(self, workspace_id: str) -> Optional[dict]:
        """Get workspace by ID, update last access"""
        with self._lock:
            workspace = self._workspaces.get(workspace_id)
            if workspace:
                workspace['last_access'] = time.time()
                # Also check Redis for cross-instance access if available
                if redis_client:
                    redis_client.hset(f"workspace:{workspace_id}", mapping={
                        'last_access': workspace['last_access'],
                        'total_size': workspace['total_size']
                    })
            return workspace
    
    def update_workspace_files(self, workspace_id: str, files: List[dict], total_size: int):
        """Update file list in workspace"""
        with self._lock:
            workspace = self._workspaces.get(workspace_id)
            if workspace:
                workspace['files'] = files
                workspace['total_size'] = total_size
                workspace['last_access'] = time.time()
                
                # Update Redis for cross-instance
                if redis_client:
                    redis_client.hset(f"workspace:{workspace_id}", mapping={
                        'total_size': total_size,
                        'last_access': workspace['last_access']
                    })
                    redis_client.setex(f"workspace_files:{workspace_id}", Config.WORKSPACE_EXPIRY, json.dumps(files))
    
    def increment_active(self, workspace_id: str):
        """Increment active extraction count"""
        with self._lock:
            workspace = self._workspaces.get(workspace_id)
            if workspace:
                workspace['active_extractions'] += 1
    
    def decrement_active(self, workspace_id: str):
        """Decrement active extraction count"""
        with self._lock:
            workspace = self._workspaces.get(workspace_id)
            if workspace:
                workspace['active_extractions'] = max(0, workspace['active_extractions'] - 1)
    
    def delete_workspace(self, workspace_id: str):
        """Delete workspace and all extracted files"""
        with self._lock:
            workspace = self._workspaces.pop(workspace_id, None)
        
        if workspace and os.path.exists(workspace['path']):
            shutil.rmtree(workspace['path'], ignore_errors=True)
        
        # Clean up Redis
        if redis_client:
            redis_client.delete(f"workspace:{workspace_id}")
            redis_client.delete(f"workspace_files:{workspace_id}")
    
    def _cleanup_loop(self):
        """Background thread to clean up expired workspaces"""
        while True:
            time.sleep(Config.CLEANUP_INTERVAL)
            now = time.time()
            expired = []
            
            with self._lock:
                for wid, ws in self._workspaces.items():
                    if now - ws['last_access'] > Config.WORKSPACE_EXPIRY:
                        if ws['active_extractions'] == 0:
                            expired.append(wid)
            
            for wid in expired:
                logger.info(f"Cleaning up expired workspace: {wid}")
                self.delete_workspace(wid)

# Global workspace manager
workspace_manager = WorkspaceManager()

# ==================== Rate Limit Key Functions ====================

def get_session_id():
    """Get or create session ID for rate limiting"""
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    return session['session_id']

def get_user_workspace():
    """Get or create workspace for current user"""
    session_id = get_session_id()
    
    # Check if user already has a workspace in this session
    if 'workspace_id' in session:
        workspace = workspace_manager.get_workspace(session['workspace_id'])
        if workspace:
            return workspace
    
    # Create new workspace
    workspace = workspace_manager.create_workspace(session_id)
    session['workspace_id'] = workspace['id']
    return workspace

# ==================== Extraction Handlers ====================

def extract_zip(filepath, extract_to):
    """Extract ZIP file"""
    files = []
    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            for member in zf.namelist():
                if member.endswith('/'):
                    continue
                extracted_path = zf.extract(member, extract_to)
                files.append({
                    'name': member,
                    'path': extracted_path,
                    'size': os.path.getsize(extracted_path)
                })
        return files
    except Exception as e:
        logger.error(f"ZIP extraction error: {e}")
        raise

def extract_tar(filepath, extract_to):
    """Extract TAR/GZ/BZ2 file"""
    files = []
    try:
        mode = 'r:gz' if filepath.endswith(('.gz', '.tgz')) else \
               'r:bz2' if filepath.endswith(('.bz2', '.tbz2')) else 'r'
        
        with tarfile.open(filepath, mode) as tf:
            for member in tf.getmembers():
                if member.isfile():
                    tf.extract(member, extract_to)
                    extracted_path = os.path.join(extract_to, member.name)
                    files.append({
                        'name': member.name,
                        'path': extracted_path,
                        'size': member.size
                    })
        return files
    except Exception as e:
        logger.error(f"TAR extraction error: {e}")
        raise

def extract_7z(filepath, extract_to):
    """Extract 7Z file"""
    if not HAS_7Z:
        raise Exception("7Z support not installed")
    
    files = []
    try:
        with py7zr.SevenZipFile(filepath, 'r') as szf:
            szf.extractall(extract_to)
            for root, _, filenames in os.walk(extract_to):
                for filename in filenames:
                    full_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(full_path, extract_to)
                    files.append({
                        'name': rel_path,
                        'path': full_path,
                        'size': os.path.getsize(full_path)
                    })
        return files
    except Exception as e:
        logger.error(f"7Z extraction error: {e}")
        raise

def extract_rar(filepath, extract_to):
    """Extract RAR file"""
    if not HAS_RAR:
        raise Exception("RAR support not installed")
    
    files = []
    try:
        with rarfile.RarFile(filepath) as rf:
            for member in rf.infolist():
                if not member.isdir():
                    rf.extract(member, extract_to)
                    extracted_path = os.path.join(extract_to, member.filename)
                    files.append({
                        'name': member.filename,
                        'path': extracted_path,
                        'size': member.file_size
                    })
        return files
    except Exception as e:
        logger.error(f"RAR extraction error: {e}")
        raise

def get_extraction_handler(filepath: str):
    """Get appropriate extraction handler based on file extension"""
    ext = filepath.split('.')[-1].lower()
    
    handlers = {
        'zip': extract_zip,
        'tar': extract_tar,
        'gz': extract_tar,
        'tgz': extract_tar,
        'bz2': extract_tar,
        'tbz2': extract_tar,
    }
    
    if ext in handlers:
        return handlers[ext]
    elif ext == '7z' and HAS_7Z:
        return extract_7z
    elif ext == 'rar' and HAS_RAR:
        return extract_rar
    else:
        raise ValueError(f"Unsupported file type: {ext}")

# ==================== Celery Task (Async Extraction) ====================

if celery:
    @celery.task(bind=True, name='extract_archive')
    def extract_archive_task(self, file_path: str, workspace_id: str, original_filename: str):
        """Background task for extracting archives"""
        try:
            # Get file extension
            ext = file_path.split('.')[-1].lower()
            workspace = workspace_manager.get_workspace(workspace_id)
            
            if not workspace:
                return {'error': 'Workspace not found'}
            
            workspace_manager.increment_active(workspace_id)
            
            # Update task progress
            self.update_state(state='PROGRESS', meta={'progress': 10, 'message': 'Starting extraction...'})
            
            # Get handler and extract
            handler = get_extraction_handler(file_path)
            extracted_files = handler(file_path, workspace['path'])
            
            self.update_state(state='PROGRESS', meta={'progress': 90, 'message': 'Processing files...'})
            
            # Prepare response
            file_list = []
            total_size = 0
            for f in extracted_files:
                total_size += f['size']
                file_list.append({
                    'name': f['name'],
                    'size': f['size'],
                    'size_formatted': format_size(f['size'])
                })
            
            # Update workspace
            workspace_manager.update_workspace_files(workspace_id, file_list, total_size)
            
            # Clean up uploaded file
            if os.path.exists(file_path):
                os.remove(file_path)
            
            workspace_manager.decrement_active(workspace_id)
            
            return {
                'success': True,
                'total_files': len(file_list),
                'total_size': total_size,
                'total_size_formatted': format_size(total_size),
                'files': file_list
            }
            
        except Exception as e:
            logger.error(f"Async extraction error: {traceback.format_exc()}")
            workspace_manager.decrement_active(workspace_id)
            return {'error': str(e)}

# ==================== Helper Functions ====================

def format_size(size_bytes: int) -> str:
    """Format file size human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

# ==================== API Endpoints ====================

@app.route('/')
@limiter.exempt
def index():
    """Main page"""
    return render_template_string(HTML_TEMPLATE_MULTI)

@app.route('/api/upload', methods=['POST'])
@limiter.limit(Config.RATE_LIMIT)
def upload_file():
    """Upload and extract archive (sync or async)"""
    try:
        # Check file
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Empty filename'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': f'File type not allowed. Allowed: {", ".join(Config.ALLOWED_EXTENSIONS)}'}), 400
        
        # Get or create workspace for this user
        workspace = get_user_workspace()
        
        # Check workspace size limit
        if workspace['total_size'] > Config.MAX_WORKSPACE_SIZE:
            return jsonify({'error': 'Workspace size limit exceeded. Please clear old files.'}), 413
        
        # Check concurrent extraction limit
        if workspace['active_extractions'] >= Config.MAX_CONCURRENT_EXTRACTIONS:
            return jsonify({'error': f'Too many concurrent extractions (max {Config.MAX_CONCURRENT_EXTRACTIONS}). Please wait.'}), 429
        
        # Save uploaded file
        ext = file.filename.rsplit('.', 1)[1].lower()
        upload_id = hashlib.md5(f"{time.time()}{file.filename}".encode()).hexdigest()[:16]
        temp_path = os.path.join(Config.UPLOAD_DIR, f"{upload_id}_{secure_filename(file.filename)}")
        file.save(temp_path)
        file_size = os.path.getsize(temp_path)
        
        logger.info(f"User {session.get('session_id')} uploaded: {file.filename} ({format_size(file_size)})")
        
        # Use Celery for async if available
        if celery and request.args.get('async') == 'true':
            task = extract_archive_task.delay(temp_path, workspace['id'], file.filename)
            return jsonify({
                'success': True,
                'async': True,
                'task_id': task.id,
                'extract_id': workspace['id']
            })
        
        # Sync extraction (fallback)
        try:
            start_time = time.time()
            handler = get_extraction_handler(temp_path)
            extracted_files = handler(temp_path, workspace['path'])
            elapsed = time.time() - start_time
            
            file_list = []
            total_size = 0
            for f in extracted_files:
                total_size += f['size']
                file_list.append({
                    'name': f['name'],
                    'size': f['size'],
                    'size_formatted': format_size(f['size'])
                })
            
            # Update workspace
            workspace_manager.update_workspace_files(workspace['id'], file_list, total_size)
            
            # Clean up uploaded file
            os.remove(temp_path)
            
            return jsonify({
                'success': True,
                'async': False,
                'extract_id': workspace['id'],
                'filename': file.filename,
                'file_size': file_size,
                'file_size_formatted': format_size(file_size),
                'total_files': len(file_list),
                'total_size': total_size,
                'total_size_formatted': format_size(total_size),
                'extract_time': round(elapsed, 2),
                'files': file_list
            })
            
        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise
            
    except Exception as e:
        logger.error(f"Upload error: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/task/<task_id>')
def get_task_status(task_id):
    """Get status of async extraction task"""
    if not celery:
        return jsonify({'error': 'Async tasks not enabled'}), 400
    
    task = extract_archive_task.AsyncResult(task_id)
    
    if task.state == 'PENDING':
        response = {'state': 'PENDING', 'progress': 0}
    elif task.state == 'PROGRESS':
        response = {'state': 'PROGRESS', **task.info}
    elif task.state == 'SUCCESS':
        response = {'state': 'SUCCESS', 'result': task.result}
    elif task.state == 'FAILURE':
        response = {'state': 'FAILURE', 'error': str(task.info)}
    else:
        response = {'state': task.state}
    
    return jsonify(response)

@app.route('/api/workspace')
def get_workspace():
    """Get current workspace info"""
    workspace = get_user_workspace()
    return jsonify({
        'success': True,
        'extract_id': workspace['id'],
        'total_files': len(workspace['files']),
        'total_size': workspace['total_size'],
        'total_size_formatted': format_size(workspace['total_size']),
        'files': workspace['files']
    })

@app.route('/api/download/<filename>')
def download_file(filename):
    """Download extracted file from user's workspace"""
    workspace = get_user_workspace()
    file_path = os.path.join(workspace['path'], filename)
    
    # Security: ensure file is within workspace
    real_path = os.path.realpath(file_path)
    if not real_path.startswith(os.path.realpath(workspace['path'])):
        return jsonify({'error': 'Invalid file path'}), 403
    
    if not os.path.exists(real_path):
        return jsonify({'error': 'File not found'}), 404
    
    return send_file(
        real_path,
        as_attachment=True,
        download_name=os.path.basename(filename)
    )

@app.route('/api/download-all')
def download_all():
    """Download all files as ZIP"""
    workspace = get_user_workspace()
    
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(workspace['path']):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, workspace['path'])
                zf.write(file_path, arcname)
    
    memory_file.seek(0)
    
    return send_file(
        memory_file,
        as_attachment=True,
        download_name=f"extracted_{workspace['id']}.zip",
        mimetype='application/zip'
    )

@app.route('/api/delete', methods=['DELETE'])
def delete_workspace():
    """Delete current user's workspace"""
    workspace = get_user_workspace()
    workspace_manager.delete_workspace(workspace['id'])
    session.pop('workspace_id', None)
    return jsonify({'success': True})

@app.route('/api/delete-file/<filename>', methods=['DELETE'])
def delete_file(filename):
    """Delete a single file from workspace"""
    workspace = get_user_workspace()
    file_path = os.path.join(workspace['path'], filename)
    
    real_path = os.path.realpath(file_path)
    if not real_path.startswith(os.path.realpath(workspace['path'])):
        return jsonify({'error': 'Invalid file path'}), 403
    
    if os.path.exists(real_path):
        os.remove(real_path)
        
        # Update workspace files list
        new_files = [f for f in workspace['files'] if f['name'] != filename]
        new_size = sum(f['size'] for f in new_files)
        workspace_manager.update_workspace_files(workspace['id'], new_files, new_size)
    
    return jsonify({'success': True})

@app.route('/api/cleanup', methods=['POST'])
@limiter.limit("5 per minute")
def force_cleanup():
    """Force cleanup of expired workspaces"""
    # This will be handled by background thread, just trigger
    return jsonify({'success': True, 'message': 'Cleanup will run in background'})

# ==================== HTML Template ====================

HTML_TEMPLATE_MULTI = '''
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Unzip Pro - Multi-User Edition</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); font-family: 'Segoe UI', sans-serif; min-height: 100vh; padding: 20px; }
        .card { border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); background: rgba(255,255,255,0.98); }
        .card-header { background: linear-gradient(135deg, #4361ee 0%, #3a0ca3 100%); color: white; border-radius: 20px 20px 0 0 !important; }
        .upload-area { border: 3px dashed #4361ee; border-radius: 20px; padding: 60px 20px; text-align: center; cursor: pointer; transition: all 0.3s; background: #f8f9fa; }
        .upload-area:hover, .upload-area.drag-over { border-color: #06ffa5; background: #e9ecef; transform: scale(1.01); }
        .stats-card { background: linear-gradient(135deg, #1e1e2f, #2d2d44); color: white; border-radius: 15px; padding: 20px; text-align: center; }
        .stats-number { font-size: 32px; font-weight: bold; color: #06ffa5; }
        .file-item { background: white; border-radius: 12px; padding: 15px; margin-bottom: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); transition: all 0.2s; }
        .file-item:hover { transform: translateX(5px); }
        .toast-notification { position: fixed; bottom: 20px; right: 20px; z-index: 9999; }
        .fade-in { animation: fadeIn 0.3s ease; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        .badge-multi { background: #06ffa5; color: #1e1e2f; }
        .session-id { font-size: 11px; font-family: monospace; background: rgba(255,255,255,0.2); padding: 4px 8px; border-radius: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-header">
                <div class="row align-items-center">
                    <div class="col-md-8">
                        <h2><i class="fas fa-users me-2"></i> Web Unzip Pro - Multi-User</h2>
                        <p class="mb-0"><i class="fas fa-globe me-1"></i> Hỗ trợ nhiều người dùng cùng lúc | Mỗi người có workspace riêng</p>
                    </div>
                    <div class="col-md-4 text-end">
                        <i class="fas fa-rocket fa-2x"></i>
                        <span class="badge bg-success ms-2">Multi-User Ready</span>
                    </div>
                </div>
                <div class="mt-2 small">
                    <i class="fas fa-fingerprint me-1"></i> Session: <span class="session-id" id="sessionId">Loading...</span>
                </div>
            </div>
            <div class="card-body p-4">
                <div class="upload-area" id="uploadArea">
                    <i class="fas fa-cloud-upload-alt fa-4x mb-3" style="color: #4361ee;"></i>
                    <h4>Kéo thả file nén vào đây</h4>
                    <p class="text-muted">Hỗ trợ ZIP, RAR, 7Z, TAR, GZ, BZ2 | Mỗi người dùng có workspace riêng biệt</p>
                    <input type="file" id="fileInput" accept=".zip,.rar,.7z,.tar,.gz,.bz2,.tgz,.tbz2" style="display: none;">
                    <button class="btn btn-primary mt-3" onclick="document.getElementById('fileInput').click()">
                        <i class="fas fa-folder-open me-2"></i> Chọn file
                    </button>
                </div>

                <div class="row mt-4 g-3" id="statsRow" style="display: none;">
                    <div class="col-md-4"><div class="stats-card"><i class="fas fa-file-archive fa-2x mb-2"></i><div class="stats-number" id="totalFiles">0</div><div>File đã giải nén</div></div></div>
                    <div class="col-md-4"><div class="stats-card"><i class="fas fa-database fa-2x mb-2"></i><div class="stats-number" id="totalSize">0</div><div>MB đã xử lý</div></div></div>
                    <div class="col-md-4"><div class="stats-card"><i class="fas fa-clock fa-2x mb-2"></i><div class="stats-number" id="extractTime">0</div><div>giây</div></div></div>
                </div>

                <div class="row mt-4" id="controlsRow" style="display: none;">
                    <div class="col-md-6"><input type="text" id="searchInput" class="form-control" placeholder="🔍 Tìm kiếm file..."></div>
                    <div class="col-md-6 text-end">
                        <button class="btn btn-outline-success me-2" id="downloadAllBtn"><i class="fas fa-download me-2"></i>Tải tất cả</button>
                        <button class="btn btn-outline-danger" id="clearAllBtn"><i class="fas fa-trash me-2"></i>Xóa tất cả</button>
                    </div>
                </div>

                <div id="fileList" class="mt-4" style="max-height: 500px; overflow-y: auto;"></div>
                <div id="queueStatus" class="mt-3"></div>
            </div>
        </div>
    </div>
    <div class="toast-notification" id="toast"></div>

    <script>
        let extractedFiles = [];
        let currentWorkspaceId = null;
        
        async function getWorkspace() {
            try {
                const res = await fetch('/api/workspace');
                const data = await res.json();
                if (data.success) {
                    currentWorkspaceId = data.extract_id;
                    extractedFiles = data.files;
                    document.getElementById('sessionId').textContent = currentWorkspaceId.substring(0, 16);
                    if (data.total_files > 0) {
                        document.getElementById('statsRow').style.display = 'flex';
                        document.getElementById('controlsRow').style.display = 'flex';
                        document.getElementById('totalFiles').textContent = data.total_files;
                        document.getElementById('totalSize').textContent = (data.total_size / (1024 * 1024)).toFixed(1);
                        renderFileList();
                    }
                }
            } catch(e) {}
        }
        
        function showToast(message, type = 'success') {
            const toast = document.getElementById('toast');
            const colors = { success: '#10b981', error: '#ef4444', info: '#3b82f6', warning: '#f59e0b' };
            toast.innerHTML = `<div class="alert fade-in" style="background: ${colors[type]}; color: white; border: none; border-radius: 12px;">
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'} me-2"></i>${message}
            </div>`;
            setTimeout(() => toast.innerHTML = '', 3000);
        }
        
        async function uploadFile(file) {
            const formData = new FormData();
            formData.append('file', file);
            
            showToast(`Đang xử lý ${file.name}...`, 'info');
            document.getElementById('queueStatus').innerHTML = '<div class="alert alert-info"><i class="fas fa-spinner fa-spin me-2"></i>Đang xử lý...</div>';
            
            try {
                const response = await fetch('/api/upload', { method: 'POST', body: formData });
                const data = await response.json();
                
                if (data.success) {
                    currentWorkspaceId = data.extract_id;
                    extractedFiles = data.files;
                    
                    document.getElementById('statsRow').style.display = 'flex';
                    document.getElementById('controlsRow').style.display = 'flex';
                    document.getElementById('totalFiles').textContent = data.total_files;
                    document.getElementById('totalSize').textContent = (data.total_size / (1024 * 1024)).toFixed(1);
                    document.getElementById('extractTime').textContent = data.extract_time || 0;
                    
                    renderFileList();
                    showToast(`✅ Thành công! ${data.total_files} file (${data.extract_time || '?'}s)`, 'success');
                } else {
                    showToast(`❌ Lỗi: ${data.error}`, 'error');
                }
            } catch (err) {
                showToast(`❌ Lỗi kết nối: ${err.message}`, 'error');
            }
            document.getElementById('queueStatus').innerHTML = '';
        }
        
        function renderFileList() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            let filtered = searchTerm ? extractedFiles.filter(f => f.name.toLowerCase().includes(searchTerm)) : extractedFiles;
            
            if (filtered.length === 0) {
                document.getElementById('fileList').innerHTML = '<div class="text-center text-muted py-5"><i class="fas fa-folder-open fa-3x mb-3"></i><br>Chưa có file nào</div>';
                return;
            }
            
            document.getElementById('fileList').innerHTML = filtered.map(file => `
                <div class="file-item fade-in">
                    <div class="row align-items-center">
                        <div class="col-auto"><i class="fas fa-file fa-2x text-primary"></i></div>
                        <div class="col">
                            <div class="fw-bold">${escapeHtml(file.name)}</div>
                            <small class="text-muted">${file.size_formatted}</small>
                        </div>
                        <div class="col-auto">
                            <button class="btn btn-sm btn-outline-primary me-2" onclick="downloadFile('${encodeURIComponent(file.name)}')"><i class="fas fa-download"></i></button>
                            <button class="btn btn-sm btn-outline-danger" onclick="deleteFile('${encodeURIComponent(file.name)}')"><i class="fas fa-trash"></i></button>
                        </div>
                    </div>
                </div>
            `).join('');
        }
        
        function escapeHtml(str) { return str.replace(/[&<>]/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[m])); }
        
        window.downloadFile = function(filename) {
            window.open(`/api/download/${filename}`, '_blank');
        };
        
        window.deleteFile = async function(filename) {
            if (confirm(`Xóa file ${filename}?`)) {
                await fetch(`/api/delete-file/${encodeURIComponent(filename)}`, { method: 'DELETE' });
                extractedFiles = extractedFiles.filter(f => f.name !== filename);
                renderFileList();
                document.getElementById('totalFiles').textContent = extractedFiles.length;
                showToast('Đã xóa', 'info');
            }
        };
        
        document.getElementById('downloadAllBtn').onclick = () => {
            if (extractedFiles.length) window.open('/api/download-all', '_blank');
        };
        
        document.getElementById('clearAllBtn').onclick = async () => {
            if (extractedFiles.length && confirm('Xóa tất cả file?')) {
                await fetch('/api/delete', { method: 'DELETE' });
                extractedFiles = [];
                renderFileList();
                document.getElementById('statsRow').style.display = 'none';
                document.getElementById('controlsRow').style.display = 'none';
                showToast('Đã xóa workspace', 'info');
            }
        };
        
        document.getElementById('searchInput').addEventListener('input', renderFileList);
        
        // Drag & Drop
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        
        uploadArea.addEventListener('dragover', e => { e.preventDefault(); uploadArea.classList.add('drag-over'); });
        uploadArea.addEventListener('dragleave', () => uploadArea.classList.remove('drag-over'));
        uploadArea.addEventListener('drop', e => { e.preventDefault(); uploadArea.classList.remove('drag-over'); uploadFile(e.dataTransfer.files[0]); });
        uploadArea.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', e => { if (e.target.files[0]) uploadFile(e.target.files[0]); fileInput.value = ''; });
        
        // Initialize
        getWorkspace();
        showToast('🚀 Web Unzip Pro Multi-User sẵn sàng | Mỗi người dùng có workspace riêng', 'success');
    </script>
</body>
</html>
'''

# ==================== Application Entry ====================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
