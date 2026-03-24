# ==================== IMPORT ====================
import os, io, zipfile, tarfile, tempfile, shutil, time, uuid, threading, logging
from datetime import datetime
from flask import Flask, request, jsonify, send_file, render_template_string, session
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
    EXTRACT_TIMEOUT = 300

    RATE_LIMIT = "10 per minute"
    ALLOWED_EXTENSIONS = {'zip', 'tar', 'gz', 'tgz', 'bz2'}

os.makedirs(Config.UPLOAD_DIR, exist_ok=True)
os.makedirs(Config.EXTRACT_DIR, exist_ok=True)

# ==================== APP ====================

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY
CORS(app)

limiter = Limiter(app=app, key_func=get_remote_address)
logging.basicConfig(level=logging.INFO)

# ==================== WORKSPACE ====================

class WorkspaceManager:
    def __init__(self):
        self.data = {}
        self.lock = threading.Lock()

    def create(self):
        wid = uuid.uuid4().hex[:16]
        path = os.path.join(Config.EXTRACT_DIR, wid)
        os.makedirs(path, exist_ok=True)

        ws = {"id": wid, "path": path, "files": [], "size": 0, "created": time.time()}
        with self.lock:
            self.data[wid] = ws
        return ws

    def get(self, wid):
        with self.lock:
            return self.data.get(wid)

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
    if not os.path.realpath(target).startswith(os.path.realpath(base)):
        raise Exception("Path traversal")
    return target

def allowed_file(name):
    return '.' in name and name.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

# ==================== EXTRACT ====================

def extract_zip(fp, out):
    files, total = [], 0
    with zipfile.ZipFile(fp) as z:
        for m in z.infolist():
            if m.is_dir(): continue
            if m.file_size > Config.MAX_FILE_SIZE: raise Exception("File too large")

            path = safe_path(out, os.path.join(out, m.filename))
            os.makedirs(os.path.dirname(path), exist_ok=True)

            with z.open(m) as src, open(path, 'wb') as dst:
                shutil.copyfileobj(src, dst, 1024*1024)

            total += m.file_size
            if total > Config.MAX_WORKSPACE_SIZE:
                raise Exception("Total size exceeded")

            files.append({"name": m.filename, "size": m.file_size})
    return files, total

def extract_tar(fp, out):
    files, total = [], 0
    with tarfile.open(fp) as t:
        for m in t.getmembers():
            if not m.isfile(): continue
            if m.size > Config.MAX_FILE_SIZE: raise Exception("File too large")

            path = safe_path(out, os.path.join(out, m.name))
            os.makedirs(os.path.dirname(path), exist_ok=True)

            with t.extractfile(m) as src, open(path, 'wb') as dst:
                shutil.copyfileobj(src, dst, 1024*1024)

            total += m.size
            if total > Config.MAX_WORKSPACE_SIZE:
                raise Exception("Total size exceeded")

            files.append({"name": m.name, "size": m.size})
    return files, total

def extract(fp, out):
    return extract_zip(fp, out) if fp.endswith(".zip") else extract_tar(fp, out)

# ==================== ROUTES ====================

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/api/upload', methods=['POST'])
@limiter.limit(Config.RATE_LIMIT)
def upload():
    if 'file' not in request.files:
        return jsonify({"error": "No file"}), 400

    f = request.files['file']
    if not allowed_file(f.filename):
        return jsonify({"error": "Invalid type"}), 400

    ws = get_workspace()

    path = os.path.join(Config.UPLOAD_DIR, uuid.uuid4().hex + "_" + secure_filename(f.filename))
    f.save(path)

    try:
        files, size = extract(path, ws["path"])

        ws["files"].extend(files)
        ws["size"] += size

        os.remove(path)

        return jsonify({"success": True, "files": ws["files"], "count": len(ws["files"])})

    except Exception as e:
        os.remove(path)
        return jsonify({"error": str(e)}), 500

@app.route('/api/download/<path:name>')
def download(name):
    ws = get_workspace()
    path = safe_path(ws["path"], os.path.join(ws["path"], name))
    return send_file(path, as_attachment=True)

@app.route('/api/download-all')
def download_all():
    ws = get_workspace()
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")

    with zipfile.ZipFile(tmp.name, 'w') as z:
        for root, _, files in os.walk(ws["path"]):
            for f in files:
                full = os.path.join(root, f)
                z.write(full, os.path.relpath(full, ws["path"]))

    return send_file(tmp.name, as_attachment=True)

# ==================== HTML FIX ====================

HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Unzip</title>
</head>
<body>

<h2>Upload ZIP/TAR (max 5GB)</h2>

<form id="uploadForm" enctype="multipart/form-data">
<input type="file" id="fileInput" name="file">
<button type="submit">Upload</button>
</form>

<div id="result"></div>

<script>
document.getElementById("uploadForm").onsubmit = async (e)=>{
    e.preventDefault();
    const file = document.getElementById("fileInput").files[0];
    if(!file){ alert("Chọn file"); return; }

    const fd = new FormData();
    fd.append("file", file);

    const res = await fetch("/api/upload",{method:"POST",body:fd});
    const data = await res.json();

    document.getElementById("result").innerText = JSON.stringify(data,null,2);
}
</script>

</body>
</html>
"""

# ==================== RUN ====================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
