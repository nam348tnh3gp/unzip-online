"""
Web Unzip Pro - Stable Multi-User Edition
- Safe extraction (anti zip-slip)
- Timeout protection
- No RAM crash (stream zip)
- Workspace isolation
- Improved concurrency
- Beautiful UI
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
from pathlib import Path
from datetime import datetime
from flask import Flask, request, jsonify, send_file, render_template_string, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename

# ==================== CONFIG ====================

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24).hex())

    # Use /tmp on Render for writable storage
    if os.environ.get('RENDER'):
        BASE_DIR = '/tmp/unzip_app'
    else:
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    
    UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
    EXTRACT_DIR = os.path.join(BASE_DIR, 'extracts')

    MAX_WORKSPACE_SIZE = 1024 * 1024 * 1024  # 1GB
    MAX_FILES = 10000
    MAX_FILE_SIZE = 200 * 1024 * 1024  # 200MB per file
    EXTRACT_TIMEOUT = 120  # seconds

    RATE_LIMIT = "20 per minute"

    ALLOWED_EXTENSIONS = {'zip', 'tar', 'gz', 'tgz', 'bz2'}

# Create directories
os.makedirs(Config.UPLOAD_DIR, exist_ok=True)
os.makedirs(Config.EXTRACT_DIR, exist_ok=True)

# ==================== APP ====================

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY
CORS(app)

limiter = Limiter(app=app, key_func=get_remote_address)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==================== WORKSPACE ====================

class WorkspaceManager:
    def __init__(self):
        self.data = {}
        self.lock = threading.Lock()

    def create(self):
        wid = uuid.uuid4().hex[:16]
        path = os.path.join(Config.EXTRACT_DIR, wid)
        os.makedirs(path, exist_ok=True)

        ws = {
            "id": wid,
            "path": path,
            "files": [],
            "size": 0,
            "created_at": time.time()
        }

        with self.lock:
            self.data[wid] = ws

        return ws

    def get(self, wid):
        with self.lock:
            return self.data.get(wid)

    def delete(self, wid):
        with self.lock:
            ws = self.data.pop(wid, None)
            if ws and os.path.exists(ws["path"]):
                shutil.rmtree(ws["path"], ignore_errors=True)
            return ws

workspace_manager = WorkspaceManager()


def get_workspace():
    if "wid" not in session:
        ws = workspace_manager.create()
        session["wid"] = ws["id"]
        return ws
    ws = workspace_manager.get(session["wid"])
    if not ws:
        ws = workspace_manager.create()
        session["wid"] = ws["id"]
    return ws


# ==================== SECURITY ====================

def safe_path(base, target):
    """Prevent zip-slip attacks"""
    real_base = os.path.realpath(base)
    real_target = os.path.realpath(target)
    if not real_target.startswith(real_base):
        raise Exception("Path traversal detected")
    return real_target


def allowed_file(name):
    return '.' in name and name.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


# ==================== TIMEOUT ====================

def run_with_timeout(func, timeout, *args):
    result = {}

    def target():
        try:
            result['data'] = func(*args)
        except Exception as e:
            result['error'] = str(e)

    t = threading.Thread(target=target)
    t.daemon = True
    t.start()
    t.join(timeout)

    if t.is_alive():
        raise Exception("Extraction timeout ({}s)".format(timeout))

    if 'error' in result:
        raise Exception(result['error'])

    return result['data']


# ==================== EXTRACT ====================

def extract_zip(filepath, out):
    """Extract ZIP with streaming and security checks"""
    files = []
    count = 0
    total_size = 0

    with zipfile.ZipFile(filepath, 'r') as z:
        for member in z.infolist():
            # Skip directories
            if member.is_dir():
                continue

            count += 1
            if count > Config.MAX_FILES:
                raise Exception("Too many files in archive (max {})".format(Config.MAX_FILES))

            if member.file_size > Config.MAX_FILE_SIZE:
                raise Exception("File too large: {} > {}MB".format(member.filename, Config.MAX_FILE_SIZE / (1024*1024)))

            # Safe path resolution
            target_path = os.path.join(out, member.filename)
            safe_path(out, target_path)

            # Create directories if needed
            os.makedirs(os.path.dirname(target_path), exist_ok=True)

            # Extract with streaming (no RAM overload)
            with z.open(member) as src, open(target_path, 'wb') as dst:
                shutil.copyfileobj(src, dst)

            files.append({
                "name": member.filename,
                "size": member.file_size,
                "size_formatted": format_size(member.file_size)
            })
            total_size += member.file_size

    return files, total_size


def extract_tar(filepath, out):
    """Extract TAR/GZ/BZ2 with streaming and security checks"""
    files = []
    count = 0
    total_size = 0

    # Determine open mode
    if filepath.endswith(('.gz', '.tgz')):
        mode = 'r:gz'
    elif filepath.endswith(('.bz2', '.tbz2')):
        mode = 'r:bz2'
    else:
        mode = 'r'

    with tarfile.open(filepath, mode) as t:
        for member in t.getmembers():
            if not member.isfile():
                continue

            count += 1
            if count > Config.MAX_FILES:
                raise Exception("Too many files in archive (max {})".format(Config.MAX_FILES))

            if member.size > Config.MAX_FILE_SIZE:
                raise Exception("File too large: {} > {}MB".format(member.name, Config.MAX_FILE_SIZE / (1024*1024)))

            # Safe path resolution
            target_path = os.path.join(out, member.name)
            safe_path(out, target_path)

            # Create directories if needed
            os.makedirs(os.path.dirname(target_path), exist_ok=True)

            # Extract with streaming
            with t.extractfile(member) as src, open(target_path, 'wb') as dst:
                shutil.copyfileobj(src, dst)

            files.append({
                "name": member.name,
                "size": member.size,
                "size_formatted": format_size(member.size)
            })
            total_size += member.size

    return files, total_size


def extract_archive(filepath, out):
    """Route to appropriate extractor"""
    if filepath.endswith('.zip'):
        return extract_zip(filepath, out)
    return extract_tar(filepath, out)


def format_size(size_bytes):
    """Format file size human readable"""
    if size_bytes == 0:
        return "0 B"
    units = ['B', 'KB', 'MB', 'GB']
    i = 0
    while size_bytes >= 1024 and i < len(units) - 1:
        size_bytes /= 1024.0
        i += 1
    return "{:.1f} {}".format(size_bytes, units[i])


# ==================== CLEANUP THREAD ====================

def cleanup_old_workspaces():
    """Remove workspaces older than 2 hours"""
    while True:
        time.sleep(3600)  # Every hour
        now = time.time()
        expired = []
        with workspace_manager.lock:
            for wid, ws in workspace_manager.data.items():
                if now - ws['created_at'] > 7200:  # 2 hours
                    expired.append(wid)
        for wid in expired:
            logger.info(f"Cleaning expired workspace: {wid}")
            workspace_manager.delete(wid)


# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_old_workspaces, daemon=True)
cleanup_thread.start()


# ==================== ROUTES ====================

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/health')
def health():
    """Health check for Render"""
    return jsonify({
        'status': 'healthy',
        'base_dir': Config.BASE_DIR,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/upload', methods=['POST'])
@limiter.limit(Config.RATE_LIMIT)
def upload():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        f = request.files['file']

        if f.filename == '':
            return jsonify({"error": "Empty filename"}), 400

        if not allowed_file(f.filename):
            return jsonify({"error": "File type not allowed. Allowed: ZIP, TAR, GZ, BZ2"}), 400

        ws = get_workspace()

        # Check workspace size
        if ws['size'] > Config.MAX_WORKSPACE_SIZE:
            return jsonify({"error": "Workspace full. Please clear old files."}), 413

        # Save uploaded file
        filename = secure_filename(f.filename)
        unique_id = uuid.uuid4().hex[:8]
        temp_path = os.path.join(Config.UPLOAD_DIR, f"{unique_id}_{filename}")
        f.save(temp_path)

        try:
            # Extract with timeout
            files, total_size = run_with_timeout(
                extract_archive, 
                Config.EXTRACT_TIMEOUT, 
                temp_path, 
                ws["path"]
            )

            # Update workspace
            ws["files"] = files
            ws["size"] = total_size

            # Clean up uploaded file
            os.remove(temp_path)

            return jsonify({
                "success": True,
                "filename": filename,
                "count": len(files),
                "total_size": total_size,
                "total_size_formatted": format_size(total_size),
                "files": files,
                "extract_time": "OK"
            })

        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise e

    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/workspace')
def get_workspace_info():
    """Get current workspace info"""
    ws = get_workspace()
    return jsonify({
        "success": True,
        "id": ws["id"],
        "files": ws["files"],
        "count": len(ws["files"]),
        "total_size": ws["size"],
        "total_size_formatted": format_size(ws["size"])
    })


@app.route('/api/download/<path:name>')
def download(name):
    """Download a single file"""
    ws = get_workspace()
    file_path = os.path.join(ws["path"], name)

    try:
        safe_path(ws["path"], file_path)
    except Exception:
        return jsonify({"error": "Invalid file path"}), 403

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    return send_file(
        file_path,
        as_attachment=True,
        download_name=os.path.basename(name)
    )


@app.route('/api/download-all')
def download_all():
    """Download all files as ZIP"""
    ws = get_workspace()

    if len(ws["files"]) == 0:
        return jsonify({"error": "No files to download"}), 400

    # Create ZIP in memory
    memory_file = io.BytesIO()

    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(ws["path"]):
            for f in files:
                full_path = os.path.join(root, f)
                arcname = os.path.relpath(full_path, ws["path"])
                zf.write(full_path, arcname)

    memory_file.seek(0)

    return send_file(
        memory_file,
        as_attachment=True,
        download_name=f"extracted_{ws['id']}.zip",
        mimetype='application/zip'
    )


@app.route('/api/delete', methods=['DELETE'])
def delete_workspace():
    """Delete current workspace"""
    ws = get_workspace()
    workspace_manager.delete(ws["id"])
    session.clear()
    return jsonify({"success": True})


@app.route('/api/delete-file/<path:name>', methods=['DELETE'])
def delete_file(name):
    """Delete a single file"""
    ws = get_workspace()
    file_path = os.path.join(ws["path"], name)

    try:
        safe_path(ws["path"], file_path)
    except Exception:
        return jsonify({"error": "Invalid file path"}), 403

    if os.path.exists(file_path):
        os.remove(file_path)

        # Update workspace
        ws["files"] = [f for f in ws["files"] if f["name"] != name]
        ws["size"] = sum(f["size"] for f in ws["files"])

    return jsonify({"success": True})


@app.route('/api/clear', methods=['DELETE'])
def clear_workspace():
    """Clear all files in workspace"""
    ws = get_workspace()
    for root, dirs, files in os.walk(ws["path"]):
        for f in files:
            os.remove(os.path.join(root, f))
    ws["files"] = []
    ws["size"] = 0
    return jsonify({"success": True})


# ==================== HTML TEMPLATE ====================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Unzip Pro - Giải nén file trực tuyến</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            font-family: 'Segoe UI', sans-serif;
            min-height: 100vh;
            padding: 20px;
        }
        .card {
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            background: rgba(255,255,255,0.98);
        }
        .card-header {
            background: linear-gradient(135deg, #4361ee 0%, #3a0ca3 100%);
            color: white;
            border-radius: 20px 20px 0 0 !important;
            padding: 25px;
        }
        .upload-area {
            border: 3px dashed #4361ee;
            border-radius: 20px;
            padding: 60px 20px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
            background: #f8f9fa;
        }
        .upload-area:hover, .upload-area.drag-over {
            border-color: #06ffa5;
            background: #e9ecef;
            transform: scale(1.01);
        }
        .stats-card {
            background: linear-gradient(135deg, #1e1e2f, #2d2d44);
            color: white;
            border-radius: 15px;
            padding: 20px;
            text-align: center;
        }
        .stats-number {
            font-size: 32px;
            font-weight: bold;
            color: #06ffa5;
        }
        .file-item {
            background: white;
            border-radius: 12px;
            padding: 15px;
            margin-bottom: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: all 0.2s;
        }
        .file-item:hover {
            transform: translateX(5px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .toast-notification {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 9999;
        }
        .fade-in {
            animation: fadeIn 0.3s ease;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .spinner-border-sm {
            width: 1rem;
            height: 1rem;
        }
        .session-id {
            font-size: 11px;
            font-family: monospace;
            background: rgba(255,255,255,0.2);
            padding: 4px 8px;
            border-radius: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-header">
                <div class="row align-items-center">
                    <div class="col-md-8">
                        <h2><i class="fas fa-file-archive me-2"></i> Web Unzip Pro</h2>
                        <p class="mb-0">Giải nén ZIP, TAR, GZ, BZ2 trực tuyến | Bảo mật | Không giới hạn</p>
                    </div>
                    <div class="col-md-4 text-end">
                        <i class="fas fa-shield-alt fa-2x"></i>
                        <span class="badge bg-success ms-2">Stable</span>
                    </div>
                </div>
                <div class="mt-2 small">
                    <i class="fas fa-fingerprint me-1"></i> Workspace ID: <span class="session-id" id="sessionId">Loading...</span>
                </div>
            </div>
            <div class="card-body p-4">
                <!-- Upload Area -->
                <div class="upload-area" id="uploadArea">
                    <i class="fas fa-cloud-upload-alt fa-4x mb-3" style="color: #4361ee;"></i>
                    <h4>Kéo thả file nén vào đây</h4>
                    <p class="text-muted">Hỗ trợ ZIP, TAR, GZ, BZ2 | Tối đa 10,000 file | Mỗi file ≤ 200MB</p>
                    <input type="file" id="fileInput" accept=".zip,.tar,.gz,.tgz,.bz2,.tbz2" style="display: none;">
                    <button class="btn btn-primary mt-3" onclick="document.getElementById('fileInput').click()">
                        <i class="fas fa-folder-open me-2"></i> Chọn file
                    </button>
                </div>

                <!-- Stats -->
                <div class="row mt-4 g-3" id="statsRow" style="display: none;">
                    <div class="col-md-4">
                        <div class="stats-card">
                            <i class="fas fa-file-archive fa-2x mb-2"></i>
                            <div class="stats-number" id="totalFiles">0</div>
                            <div>File đã giải nén</div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="stats-card">
                            <i class="fas fa-database fa-2x mb-2"></i>
                            <div class="stats-number" id="totalSize">0</div>
                            <div>Dung lượng</div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="stats-card">
                            <i class="fas fa-check-circle fa-2x mb-2"></i>
                            <div class="stats-number" id="status">✅</div>
                            <div>Trạng thái</div>
                        </div>
                    </div>
                </div>

                <!-- Controls -->
                <div class="row mt-4" id="controlsRow" style="display: none;">
                    <div class="col-md-6">
                        <input type="text" id="searchInput" class="form-control" placeholder="🔍 Tìm kiếm file...">
                    </div>
                    <div class="col-md-6 text-end">
                        <button class="btn btn-outline-success me-2" id="downloadAllBtn">
                            <i class="fas fa-download me-2"></i>Tải tất cả
                        </button>
                        <button class="btn btn-outline-danger" id="clearAllBtn">
                            <i class="fas fa-trash me-2"></i>Xóa tất cả
                        </button>
                    </div>
                </div>

                <!-- File List -->
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
                    currentWorkspaceId = data.id;
                    extractedFiles = data.files;
                    document.getElementById('sessionId').textContent = currentWorkspaceId;
                    if (data.count > 0) {
                        document.getElementById('statsRow').style.display = 'flex';
                        document.getElementById('controlsRow').style.display = 'flex';
                        document.getElementById('totalFiles').textContent = data.count;
                        document.getElementById('totalSize').textContent = data.total_size_formatted;
                        renderFileList();
                    }
                }
            } catch(e) {
                console.error(e);
            }
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
            document.getElementById('queueStatus').innerHTML = '<div class="alert alert-info"><i class="fas fa-spinner fa-spin me-2"></i>Đang giải nén...</div>';

            try {
                const response = await fetch('/api/upload', { method: 'POST', body: formData });
                const data = await response.json();

                if (data.success) {
                    extractedFiles = data.files;
                    currentWorkspaceId = data.workspace_id;

                    document.getElementById('statsRow').style.display = 'flex';
                    document.getElementById('controlsRow').style.display = 'flex';
                    document.getElementById('totalFiles').textContent = data.count;
                    document.getElementById('totalSize').textContent = data.total_size_formatted;

                    renderFileList();
                    showToast(`✅ Thành công! ${data.count} file (${data.total_size_formatted})`, 'success');
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
                        <div class="col-auto">
                            <i class="fas fa-file fa-2x text-primary"></i>
                        </div>
                        <div class="col">
                            <div class="fw-bold">${escapeHtml(file.name)}</div>
                            <small class="text-muted">${file.size_formatted || formatSize(file.size)}</small>
                        </div>
                        <div class="col-auto">
                            <button class="btn btn-sm btn-outline-primary me-2" onclick="downloadFile('${encodeURIComponent(file.name)}')">
                                <i class="fas fa-download"></i>
                            </button>
                            <button class="btn btn-sm btn-outline-danger" onclick="deleteFile('${encodeURIComponent(file.name)}')">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </div>
                </div>
            `).join('');
        }

        function formatSize(bytes) {
            if (bytes === 0) return '0 B';
            const units = ['B', 'KB', 'MB', 'GB'];
            let i = 0;
            while (bytes >= 1024 && i < units.length - 1) {
                bytes /= 1024;
                i++;
            }
            return bytes.toFixed(1) + ' ' + units[i];
        }

        function escapeHtml(str) {
            return str.replace(/[&<>]/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[m]));
        }

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
                await fetch('/api/clear', { method: 'DELETE' });
                extractedFiles = [];
                renderFileList();
                document.getElementById('statsRow').style.display = 'none';
                document.getElementById('controlsRow').style.display = 'none';
                showToast('Đã xóa tất cả', 'info');
            }
        };

        document.getElementById('searchInput').addEventListener('input', renderFileList);

        // Drag & Drop
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');

        uploadArea.addEventListener('dragover', e => { e.preventDefault(); uploadArea.classList.add('drag-over'); });
        uploadArea.addEventListener('dragleave', () => uploadArea.classList.remove('drag-over'));
        uploadArea.addEventListener('drop', e => {
            e.preventDefault();
            uploadArea.classList.remove('drag-over');
            uploadFile(e.dataTransfer.files[0]);
        });
        uploadArea.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', e => {
            if (e.target.files[0]) uploadFile(e.target.files[0]);
            fileInput.value = '';
        });

        getWorkspace();
        showToast('🚀 Web Unzip Pro sẵn sàng! Kéo thả file ZIP/TAR vào đây.', 'success');
    </script>
</body>
</html>
"""

# ==================== RUN ====================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
