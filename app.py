# ==================== IMPORT ====================
import os
import io
import zipfile
import tarfile
import tempfile
import shutil
import time
import uuid
import threading
import logging
import mimetypes
import base64
from datetime import datetime
from flask import Flask, request, jsonify, send_file, render_template_string, session, Response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename

# ==================== CONFIG ====================

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24).hex())

    BASE_DIR = '/tmp/unzip_app' if os.environ.get('RENDER') else os.getcwd()
    UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
    EXTRACT_DIR = os.path.join(BASE_DIR, 'extracts')

    MAX_CONTENT_LENGTH = 5 * 1024 * 1024 * 1024  # 🔥 5GB upload
    MAX_WORKSPACE_SIZE = 5 * 1024 * 1024 * 1024  # 🔥 5GB extract
    MAX_FILES = 20000
    MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB/file
    MAX_PREVIEW_SIZE = 10 * 1024 * 1024  # 10MB max for preview
    EXTRACT_TIMEOUT = 300

    RATE_LIMIT = "10 per minute"
    ALLOWED_EXTENSIONS = {'zip', 'tar', 'gz', 'tgz', 'bz2'}
    
    # Preview allowed extensions
    TEXT_EXTENSIONS = {'txt', 'log', 'json', 'xml', 'html', 'htm', 'css', 'js', 'py', 'java', 'c', 'cpp', 'h', 'md', 'ini', 'cfg', 'conf', 'csv', 'tsv', 'yaml', 'yml', 'sh', 'bat', 'ps1'}
    IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg', 'ico'}

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
            "created": time.time()
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


def format_size(size_bytes):
    """Format file size human readable"""
    if size_bytes == 0:
        return "0 B"
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    while size_bytes >= 1024 and i < len(units) - 1:
        size_bytes /= 1024.0
        i += 1
    return "{:.1f} {}".format(size_bytes, units[i])


def get_file_type(filename):
    """Detect file type for preview"""
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    
    if ext in Config.TEXT_EXTENSIONS:
        return 'text'
    elif ext in Config.IMAGE_EXTENSIONS:
        return 'image'
    else:
        return 'binary'


# ==================== SECURITY ====================

def safe_path(base, target):
    real_base = os.path.realpath(base)
    real_target = os.path.realpath(target)
    if not real_target.startswith(real_base):
        raise Exception("Path traversal detected")
    return real_target


def allowed_file(name):
    return '.' in name and name.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


# ==================== EXTRACT ====================

def extract_zip(fp, out):
    files, total = [], 0
    count = 0

    with zipfile.ZipFile(fp, 'r') as z:
        for m in z.infolist():
            if m.is_dir():
                continue

            count += 1
            if count > Config.MAX_FILES:
                raise Exception("Too many files (max {})".format(Config.MAX_FILES))

            if m.file_size > Config.MAX_FILE_SIZE:
                raise Exception("File too large: {} > 500MB".format(m.filename))

            path = safe_path(out, os.path.join(out, m.filename))
            os.makedirs(os.path.dirname(path), exist_ok=True)

            with z.open(m) as src, open(path, 'wb') as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)

            total += m.file_size
            if total > Config.MAX_WORKSPACE_SIZE:
                raise Exception("Total size exceeded (max 5GB)")

            files.append({
                "name": m.filename,
                "size": m.file_size,
                "size_formatted": format_size(m.file_size),
                "type": get_file_type(m.filename)
            })

    return files, total


def extract_tar(fp, out):
    files, total = [], 0
    count = 0

    # Determine open mode
    if fp.endswith(('.gz', '.tgz')):
        mode = 'r:gz'
    elif fp.endswith(('.bz2', '.tbz2')):
        mode = 'r:bz2'
    else:
        mode = 'r'

    with tarfile.open(fp, mode) as t:
        for m in t.getmembers():
            if not m.isfile():
                continue

            count += 1
            if count > Config.MAX_FILES:
                raise Exception("Too many files (max {})".format(Config.MAX_FILES))

            if m.size > Config.MAX_FILE_SIZE:
                raise Exception("File too large: {} > 500MB".format(m.name))

            path = safe_path(out, os.path.join(out, m.name))
            os.makedirs(os.path.dirname(path), exist_ok=True)

            with t.extractfile(m) as src, open(path, 'wb') as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)

            total += m.size
            if total > Config.MAX_WORKSPACE_SIZE:
                raise Exception("Total size exceeded (max 5GB)")

            files.append({
                "name": m.name,
                "size": m.size,
                "size_formatted": format_size(m.size),
                "type": get_file_type(m.name)
            })

    return files, total


def extract_archive(fp, out):
    if fp.endswith('.zip'):
        return extract_zip(fp, out)
    return extract_tar(fp, out)


# ==================== CLEANUP THREAD ====================

def cleanup_old_workspaces():
    """Remove workspaces older than 2 hours"""
    while True:
        time.sleep(3600)
        now = time.time()
        expired = []
        with workspace_manager.lock:
            for wid, ws in workspace_manager.data.items():
                if now - ws['created'] > 7200:  # 2 hours
                    expired.append(wid)
        for wid in expired:
            logger.info(f"Cleaning expired workspace: {wid}")
            workspace_manager.delete(wid)


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
            return jsonify({"error": "Invalid file type. Allowed: ZIP, TAR, GZ, BZ2"}), 400

        ws = get_workspace()

        # Check workspace capacity
        if ws["size"] > Config.MAX_WORKSPACE_SIZE:
            return jsonify({"error": "Workspace full. Clear old files first."}), 413

        # Save uploaded file
        filename = secure_filename(f.filename)
        unique_id = uuid.uuid4().hex[:8]
        temp_path = os.path.join(Config.UPLOAD_DIR, f"{unique_id}_{filename}")
        f.save(temp_path)

        try:
            start_time = time.time()
            files, total_size = extract_archive(temp_path, ws["path"])
            elapsed = time.time() - start_time

            # Update workspace
            ws["files"].extend(files)
            ws["size"] += total_size

            # Clean up uploaded file
            os.remove(temp_path)

            return jsonify({
                "success": True,
                "filename": filename,
                "count": len(files),
                "total_files": len(ws["files"]),
                "total_size": ws["size"],
                "total_size_formatted": format_size(ws["size"]),
                "files": ws["files"],
                "extract_time": round(elapsed, 2)
            })

        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            logger.error(f"Extraction error: {str(e)}")
            return jsonify({"error": str(e)}), 500

    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/preview/<path:name>')
def preview_file(name):
    """Preview file content (text or image)"""
    ws = get_workspace()
    file_path = os.path.join(ws["path"], name)

    try:
        safe_path(ws["path"], file_path)
    except Exception:
        return jsonify({"error": "Invalid file path"}), 403

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    file_size = os.path.getsize(file_path)
    file_type = get_file_type(name)
    
    if file_size > Config.MAX_PREVIEW_SIZE:
        return jsonify({
            "error": f"File too large for preview (max {format_size(Config.MAX_PREVIEW_SIZE)})",
            "size": file_size,
            "size_formatted": format_size(file_size)
        }), 413
    
    try:
        if file_type == 'text':
            # Read text file
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(500000)  # Limit to 500KB for display
                return jsonify({
                    "success": True,
                    "type": "text",
                    "name": name,
                    "size": file_size,
                    "size_formatted": format_size(file_size),
                    "content": content
                })
        elif file_type == 'image':
            # Return image as base64
            with open(file_path, 'rb') as f:
                img_data = base64.b64encode(f.read()).decode('utf-8')
                mime_type = mimetypes.guess_type(name)[0] or 'image/jpeg'
                return jsonify({
                    "success": True,
                    "type": "image",
                    "name": name,
                    "size": file_size,
                    "size_formatted": format_size(file_size),
                    "data": f"data:{mime_type};base64,{img_data}"
                })
        else:
            return jsonify({
                "success": False,
                "error": "File type not previewable",
                "type": "binary"
            }), 400
            
    except Exception as e:
        return jsonify({"error": f"Preview failed: {str(e)}"}), 500


@app.route('/api/download/<path:name>')
def download(name):
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


@app.route('/api/delete-file/<path:name>', methods=['DELETE'])
def delete_file(name):
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
    ws = get_workspace()
    for root, _, files in os.walk(ws["path"]):
        for f in files:
            try:
                os.remove(os.path.join(root, f))
            except:
                pass
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
    <title>Web Unzip Pro - Giải nén và xem file trực tuyến</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1600px; margin: 0 auto; }
        .card {
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            background: rgba(255,255,255,0.98);
            overflow: hidden;
        }
        .card-header {
            background: linear-gradient(135deg, #4361ee 0%, #3a0ca3 100%);
            color: white;
            padding: 25px 30px;
            border-bottom: none;
        }
        .upload-area {
            border: 3px dashed #4361ee;
            border-radius: 20px;
            padding: 60px 20px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            background: #f8f9fa;
            margin: 20px;
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
            transition: transform 0.2s;
        }
        .stats-card:hover { transform: translateY(-5px); }
        .stats-number {
            font-size: 32px;
            font-weight: bold;
            color: #06ffa5;
        }
        .file-item {
            background: white;
            border-radius: 12px;
            padding: 12px 15px;
            margin-bottom: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: all 0.2s;
            border-left: 4px solid #4361ee;
        }
        .file-item:hover {
            transform: translateX(5px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            border-left-color: #06ffa5;
        }
        .file-type-icon {
            width: 32px;
            text-align: center;
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
        .session-id {
            font-size: 11px;
            font-family: monospace;
            background: rgba(255,255,255,0.2);
            padding: 4px 12px;
            border-radius: 20px;
        }
        .progress-bar-custom {
            height: 6px;
            background: #e0e0e0;
            border-radius: 3px;
            overflow: hidden;
            margin: 0 20px 10px 20px;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #06ffa5, #00c46a);
            width: 0%;
            transition: width 0.3s;
        }
        .search-box {
            border-radius: 25px;
            padding: 10px 20px;
            border: 1px solid #ddd;
            transition: all 0.3s;
        }
        .search-box:focus {
            border-color: #4361ee;
            box-shadow: 0 0 0 3px rgba(67,97,238,0.1);
            outline: none;
        }
        .btn-custom {
            border-radius: 25px;
            padding: 8px 20px;
            font-weight: 500;
            transition: all 0.2s;
        }
        .btn-custom:hover { transform: scale(1.02); }
        
        /* Preview Modal */
        .modal-preview {
            max-width: 90vw;
            width: auto;
        }
        .preview-content {
            max-height: 70vh;
            overflow: auto;
            background: #1e1e2e;
            color: #e0e0e0;
            padding: 20px;
            border-radius: 12px;
            font-family: 'Monaco', monospace;
            font-size: 13px;
            white-space: pre-wrap;
            word-break: break-all;
        }
        .preview-image {
            max-width: 100%;
            max-height: 60vh;
            object-fit: contain;
        }
        .file-tag {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: bold;
            margin-left: 8px;
        }
        .tag-text { background: #3b82f6; color: white; }
        .tag-image { background: #10b981; color: white; }
        .tag-binary { background: #6b7280; color: white; }
        footer {
            text-align: center;
            padding: 20px;
            color: rgba(255,255,255,0.6);
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-header">
                <div class="row align-items-center">
                    <div class="col-md-7">
                        <h2><i class="fas fa-file-archive me-2"></i> Web Unzip Pro</h2>
                        <p class="mb-0 mt-1">Giải nén và xem nội dung ZIP, TAR, GZ, BZ2 | Xem trực tiếp file text, ảnh</p>
                    </div>
                    <div class="col-md-5 text-end">
                        <span class="badge bg-success me-2"><i class="fas fa-check-circle"></i> Unlimited</span>
                        <span class="badge bg-warning text-dark"><i class="fas fa-eye"></i> Preview</span>
                        <div class="mt-2 small">
                            <i class="fas fa-fingerprint me-1"></i> Workspace: <span class="session-id" id="sessionId">Loading...</span>
                        </div>
                    </div>
                </div>
            </div>
            <div class="card-body p-4">
                <!-- Upload Area -->
                <div class="upload-area" id="uploadArea">
                    <i class="fas fa-cloud-upload-alt fa-4x mb-3" style="color: #4361ee;"></i>
                    <h4>Kéo thả file nén vào đây</h4>
                    <p class="text-muted">Hỗ trợ ZIP, TAR, GZ, BZ2 | Xem nội dung file text và ảnh sau khi giải nén</p>
                    <input type="file" id="fileInput" accept=".zip,.tar,.gz,.tgz,.bz2,.tbz2" style="display: none;">
                    <button type="button" class="btn btn-primary mt-3" id="selectFileBtn">
                        <i class="fas fa-folder-open me-2"></i> Chọn file
                    </button>
                </div>

                <!-- Progress Bar -->
                <div class="progress-bar-custom" id="progressContainer" style="display: none;">
                    <div class="progress-fill" id="progressFill"></div>
                </div>

                <!-- Stats -->
                <div class="row mt-4 g-3" id="statsRow" style="display: none;">
                    <div class="col-md-3 col-6">
                        <div class="stats-card">
                            <i class="fas fa-file-archive fa-2x mb-2"></i>
                            <div class="stats-number" id="totalFiles">0</div>
                            <div>File đã giải nén</div>
                        </div>
                    </div>
                    <div class="col-md-3 col-6">
                        <div class="stats-card">
                            <i class="fas fa-database fa-2x mb-2"></i>
                            <div class="stats-number" id="totalSize">0</div>
                            <div>Dung lượng</div>
                        </div>
                    </div>
                    <div class="col-md-3 col-6">
                        <div class="stats-card">
                            <i class="fas fa-clock fa-2x mb-2"></i>
                            <div class="stats-number" id="extractTime">0</div>
                            <div>Giây</div>
                        </div>
                    </div>
                    <div class="col-md-3 col-6">
                        <div class="stats-card">
                            <i class="fas fa-chart-line fa-2x mb-2"></i>
                            <div class="stats-number" id="workspaceSize">0</div>
                            <div>Workspace</div>
                        </div>
                    </div>
                </div>

                <!-- Controls -->
                <div class="row mt-4" id="controlsRow" style="display: none;">
                    <div class="col-md-5">
                        <input type="text" id="searchInput" class="form-control search-box" placeholder="🔍 Tìm kiếm file theo tên...">
                    </div>
                    <div class="col-md-7 text-end">
                        <button type="button" class="btn btn-outline-success btn-custom me-2" id="downloadAllBtn">
                            <i class="fas fa-download me-2"></i>Tải tất cả (ZIP)
                        </button>
                        <button type="button" class="btn btn-outline-danger btn-custom" id="clearAllBtn">
                            <i class="fas fa-trash-alt me-2"></i>Xóa tất cả
                        </button>
                    </div>
                </div>

                <!-- File List -->
                <div id="fileList" class="mt-4" style="max-height: 500px; overflow-y: auto;"></div>
                <div id="queueStatus" class="mt-3"></div>
            </div>
        </div>
        <footer>
            <i class="fas fa-lock"></i> Dữ liệu được xử lý trên server, tự động xóa sau 2 giờ
        </footer>
    </div>

    <!-- Preview Modal -->
    <div class="modal fade" id="previewModal" tabindex="-1">
        <div class="modal-dialog modal-preview modal-lg">
            <div class="modal-content" style="background: #2d2d44; color: white;">
                <div class="modal-header border-secondary">
                    <h5 class="modal-title" id="previewTitle">Xem file</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body p-0" id="previewBody">
                    <div class="text-center p-5">Đang tải...</div>
                </div>
                <div class="modal-footer border-secondary">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Đóng</button>
                    <button type="button" class="btn btn-primary" id="previewDownloadBtn">Tải xuống</button>
                </div>
            </div>
        </div>
    </div>

    <div class="toast-notification" id="toast"></div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let extractedFiles = [];
        let currentWorkspaceId = null;
        let startTime = null;
        let previewModal = null;
        let currentPreviewFile = null;

        // DOM elements
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const selectFileBtn = document.getElementById('selectFileBtn');
        const downloadAllBtn = document.getElementById('downloadAllBtn');
        const clearAllBtn = document.getElementById('clearAllBtn');
        const searchInput = document.getElementById('searchInput');

        async function getWorkspace() {
            try {
                const res = await fetch('/api/workspace');
                const data = await res.json();
                if (data.success) {
                    currentWorkspaceId = data.id;
                    extractedFiles = data.files || [];
                    document.getElementById('sessionId').textContent = currentWorkspaceId;
                    if (data.count > 0) {
                        document.getElementById('statsRow').style.display = 'flex';
                        document.getElementById('controlsRow').style.display = 'flex';
                        document.getElementById('totalFiles').textContent = data.count;
                        document.getElementById('totalSize').textContent = data.total_size_formatted;
                        document.getElementById('workspaceSize').textContent = data.total_size_formatted;
                        renderFileList();
                    }
                }
            } catch(e) { 
                console.error('getWorkspace error:', e);
            }
        }

        function showToast(message, type = 'success') {
            const toast = document.getElementById('toast');
            const colors = { success: '#10b981', error: '#ef4444', info: '#3b82f6', warning: '#f59e0b' };
            toast.innerHTML = `<div class="alert fade-in" style="background: ${colors[type]}; color: white; border: none; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.2);">
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'} me-2"></i>${message}
            </div>`;
            setTimeout(() => toast.innerHTML = '', 3000);
        }

        function showProgress(show, percent = 0) {
            const container = document.getElementById('progressContainer');
            const fill = document.getElementById('progressFill');
            if (show) {
                container.style.display = 'block';
                fill.style.width = percent + '%';
            } else {
                container.style.display = 'none';
                fill.style.width = '0%';
            }
        }

        async function previewFile(filename) {
            currentPreviewFile = filename;
            const modal = new bootstrap.Modal(document.getElementById('previewModal'));
            const previewBody = document.getElementById('previewBody');
            const previewTitle = document.getElementById('previewTitle');
            
            previewTitle.innerHTML = `<i class="fas fa-eye me-2"></i>${filename}`;
            previewBody.innerHTML = '<div class="text-center p-5"><i class="fas fa-spinner fa-spin fa-2x mb-3"></i><br>Đang tải...</div>';
            modal.show();
            
            try {
                const res = await fetch(`/api/preview/${encodeURIComponent(filename)}`);
                const data = await res.json();
                
                if (data.success) {
                    if (data.type === 'text') {
                        previewBody.innerHTML = `
                            <div class="preview-content">
                                <div class="mb-2 text-muted small">
                                    <i class="fas fa-file-alt me-1"></i> ${data.size_formatted} | UTF-8 Text
                                </div>
                                <pre style="margin:0; white-space:pre-wrap; word-break:break-all;">${escapeHtml(data.content)}</pre>
                            </div>
                        `;
                    } else if (data.type === 'image') {
                        previewBody.innerHTML = `
                            <div class="text-center p-4">
                                <div class="mb-2 text-muted small">${data.size_formatted}</div>
                                <img src="${data.data}" class="preview-image" alt="${filename}">
                            </div>
                        `;
                    }
                } else {
                    previewBody.innerHTML = `
                        <div class="alert alert-danger m-4">
                            <i class="fas fa-exclamation-triangle me-2"></i> ${data.error || 'Không thể xem file này'}
                        </div>
                    `;
                }
            } catch (err) {
                previewBody.innerHTML = `
                    <div class="alert alert-danger m-4">
                        <i class="fas fa-exclamation-triangle me-2"></i> Lỗi: ${err.message}
                    </div>
                `;
            }
        }
        
        document.getElementById('previewDownloadBtn').addEventListener('click', () => {
            if (currentPreviewFile) {
                window.open(`/api/download/${encodeURIComponent(currentPreviewFile)}`, '_blank');
            }
        });

        async function uploadFile(file) {
            if (!file) {
                showToast('Vui lòng chọn file', 'warning');
                return;
            }

            const allowedExts = ['zip', 'tar', 'gz', 'tgz', 'bz2', 'tbz2'];
            const ext = file.name.split('.').pop().toLowerCase();
            if (!allowedExts.includes(ext)) {
                showToast('Định dạng file không được hỗ trợ. Chỉ hỗ trợ: ZIP, TAR, GZ, BZ2', 'error');
                return;
            }

            const formData = new FormData();
            formData.append('file', file);
            startTime = Date.now();

            showToast(`📦 Đang xử lý ${file.name}...`, 'info');
            showProgress(true, 20);
            document.getElementById('queueStatus').innerHTML = '<div class="alert alert-info"><i class="fas fa-spinner fa-spin me-2"></i>Đang giải nén, vui lòng chờ...</div>';

            try {
                const response = await fetch('/api/upload', { method: 'POST', body: formData });
                const data = await response.json();

                if (!response.ok) throw new Error(data.error || 'Upload failed');

                const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
                document.getElementById('extractTime').textContent = elapsed;

                if (data.success) {
                    extractedFiles = data.files || [];
                    document.getElementById('statsRow').style.display = 'flex';
                    document.getElementById('controlsRow').style.display = 'flex';
                    document.getElementById('totalFiles').textContent = extractedFiles.length;
                    document.getElementById('totalSize').textContent = data.total_size_formatted || formatSize(data.total_size);
                    document.getElementById('workspaceSize').textContent = data.total_size_formatted || formatSize(data.total_size);
                    renderFileList();
                    showProgress(false);
                    showToast(`✅ Thành công! ${extractedFiles.length} file (${data.total_size_formatted}) - ${elapsed}s`, 'success');
                } else {
                    throw new Error(data.error || 'Unknown error');
                }
            } catch (err) {
                console.error('Upload error:', err);
                showProgress(false);
                showToast(`❌ Lỗi: ${err.message}`, 'error');
            }
            document.getElementById('queueStatus').innerHTML = '';
        }

        function renderFileList() {
            const searchTerm = searchInput.value.toLowerCase();
            let filtered = searchTerm ? extractedFiles.filter(f => f.name.toLowerCase().includes(searchTerm)) : extractedFiles;

            if (!filtered || filtered.length === 0) {
                document.getElementById('fileList').innerHTML = '<div class="text-center text-muted py-5"><i class="fas fa-folder-open fa-3x mb-3"></i><br>Chưa có file nào. Hãy kéo thả file nén vào bên trên.</div>';
                return;
            }

            document.getElementById('fileList').innerHTML = filtered.map(file => {
                let icon = 'fa-file';
                let tagClass = 'tag-binary';
                let tagText = 'BIN';
                
                if (file.type === 'text') {
                    icon = 'fa-file-alt';
                    tagClass = 'tag-text';
                    tagText = 'TXT';
                } else if (file.type === 'image') {
                    icon = 'fa-file-image';
                    tagClass = 'tag-image';
                    tagText = 'IMG';
                }
                
                return `
                <div class="file-item fade-in">
                    <div class="row align-items-center">
                        <div class="col-auto file-type-icon">
                            <i class="fas ${icon} fa-lg text-primary"></i>
                        </div>
                        <div class="col">
                            <div class="fw-bold">
                                ${escapeHtml(file.name)}
                                <span class="file-tag ${tagClass}">${tagText}</span>
                            </div>
                            <small class="text-muted">${file.size_formatted || formatSize(file.size)}</small>
                        </div>
                        <div class="col-auto">
                            <button type="button" class="btn btn-sm btn-outline-info me-1" onclick="previewFile('${encodeURIComponent(file.name)}')" title="Xem trước">
                                <i class="fas fa-eye"></i>
                            </button>
                            <button type="button" class="btn btn-sm btn-outline-primary me-1" onclick="downloadFile('${encodeURIComponent(file.name)}')" title="Tải xuống">
                                <i class="fas fa-download"></i>
                            </button>
                            <button type="button" class="btn btn-sm btn-outline-danger" onclick="deleteFile('${encodeURIComponent(file.name)}')" title="Xóa">
                                <i class="fas fa-trash-alt"></i>
                            </button>
                        </div>
                    </div>
                </div>
            `}).join('');
        }

        function formatSize(bytes) {
            if (!bytes || bytes === 0) return '0 B';
            const units = ['B', 'KB', 'MB', 'GB'];
            let i = 0;
            let size = bytes;
            while (size >= 1024 && i < units.length - 1) {
                size /= 1024;
                i++;
            }
            return size.toFixed(1) + ' ' + units[i];
        }

        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/[&<>]/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[m]));
        }

        window.downloadFile = function(filename) {
            if (!filename) return;
            window.open(`/api/download/${filename}`, '_blank');
            showToast(`📥 Đang tải ${filename}`, 'info');
        };

        window.deleteFile = async function(filename) {
            if (!filename) return;
            if (confirm(`Xóa file "${filename}"?`)) {
                const res = await fetch(`/api/delete-file/${encodeURIComponent(filename)}`, { method: 'DELETE' });
                if (res.ok) {
                    extractedFiles = extractedFiles.filter(f => f.name !== filename);
                    renderFileList();
                    document.getElementById('totalFiles').textContent = extractedFiles.length;
                    showToast('Đã xóa', 'info');
                } else {
                    showToast('Xóa thất bại', 'error');
                }
            }
        };

        // Event listeners
        selectFileBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            fileInput.click();
        });

        fileInput.addEventListener('change', (e) => {
            if (e.target.files && e.target.files.length > 0) {
                uploadFile(e.target.files[0]);
            }
            fileInput.value = '';
        });

        downloadAllBtn.addEventListener('click', () => {
            if (extractedFiles && extractedFiles.length) {
                window.open('/api/download-all', '_blank');
                showToast(`📦 Đang tải ${extractedFiles.length} file...`, 'info');
            } else {
                showToast('Không có file để tải', 'warning');
            }
        });

        clearAllBtn.addEventListener('click', async () => {
            if (extractedFiles && extractedFiles.length && confirm('Xóa TẤT CẢ file trong workspace?')) {
                const res = await fetch('/api/clear', { method: 'DELETE' });
                if (res.ok) {
                    extractedFiles = [];
                    renderFileList();
                    document.getElementById('statsRow').style.display = 'none';
                    document.getElementById('controlsRow').style.display = 'none';
                    showToast('Đã xóa toàn bộ workspace', 'success');
                } else {
                    showToast('Xóa thất bại', 'error');
                }
            }
        });

        searchInput.addEventListener('input', renderFileList);

        // Drag & Drop
        uploadArea.addEventListener('dragover', (e) => { 
            e.preventDefault(); 
            uploadArea.classList.add('drag-over'); 
        });
        
        uploadArea.addEventListener('dragleave', () => { 
            uploadArea.classList.remove('drag-over'); 
        });
        
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('drag-over');
            const file = e.dataTransfer.files[0];
            if (file) {
                uploadFile(file);
            } else {
                showToast('Vui lòng kéo thả file nén', 'warning');
            }
        });

        // Khởi tạo
        getWorkspace();
        showToast('🚀 Web Unzip Pro sẵn sàng! Kéo thả file ZIP/TAR/GZ vào đây.', 'success');
    </script>
</body>
</html>
"""

# ==================== RUN ====================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
