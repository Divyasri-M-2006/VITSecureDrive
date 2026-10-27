"""
Flask app with ClamAV + heuristic scanning, AES/RSA encryption, and Google Drive upload.
"""
import os, io, socket, tempfile, pickle, subprocess, math
from flask import Flask, request, render_template, send_file
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from google_auth_oauthlib.flow import InstalledAppFlow

# --------- Config ----------
CREDENTIALS_FILE = "credentials.json"
TOKEN_FILE = "token.pickle"
SCOPES = ["https://www.googleapis.com/auth/drive.file"]
RSA_PUBLIC_PEM = "public.pem"
CLAMSCAN_CMD = "clamscan"
app = Flask(__name__)

# --------- Utility: Get free port ----------
def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

# --------- Google Drive ----------
def get_drive_service():
    creds = None
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "rb") as f:
            creds = pickle.load(f)
    if not creds or not getattr(creds, "valid", False):
        raise Exception("Drive creds missing or invalid — visit /authorize first.")
    return build("drive", "v3", credentials=creds)

# --------- ClamAV Scan ----------
def clamav_scan_file(path, timeout=120):
    try:
        proc = subprocess.run([CLAMSCAN_CMD, "--no-summary", path],
                              capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return False, f"clamscan not found ({CLAMSCAN_CMD})"
    except subprocess.TimeoutExpired:
        return False, "clamscan timed out"
    out = proc.stdout + proc.stderr
    if proc.returncode == 0:
        return True, out
    elif proc.returncode == 1:
        return False, out
    else:
        return False, "clamscan error: " + out

# --------- Heuristic Scan ----------
SUSPICIOUS_EXT = {'.exe', '.dll', '.js', '.vbs', '.bat', '.cmd', '.scr', '.ps1', '.jar'}
SAFE_EXT = {'.txt', '.pdf', '.docx', '.xlsx', '.pptx', '.csv'}
SUSPICIOUS_KEYWORDS = [
    b'CreateRemoteThread', b'VirtualAlloc', b'GetProcAddress', b'LoadLibrary',
    b'WinExec', b'ShellExecute', b'cmd.exe', b'powershell', b'HTTP', b'POST',
    b'Socket', b'Shellcode', b'Rundll32'
]

def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

def heuristic_scan(filename: str, data: bytes):
    """Check for risky patterns using simple heuristics."""
    ext = os.path.splitext(filename)[1].lower()
    if ext in SAFE_EXT:
        return 'clean', {'reason': 'safe_extension'}
    
    flags = []
    if ext in SUSPICIOUS_EXT:
        flags.append('bad_extension')

    ent = shannon_entropy(data[:2_000_000])
    if ent >= 7.5:
        flags.append('high_entropy')

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in data:
            flags.append('suspicious_keyword')
            break

    if 'bad_extension' in flags and ('high_entropy' in flags or 'suspicious_keyword' in flags):
        return 'malicious', {'flags': flags, 'entropy': ent}
    elif flags:
        return 'suspicious', {'flags': flags, 'entropy': ent}
    else:
        return 'clean', {'flags': flags, 'entropy': ent}

# Combine both scans
def full_scan(filename, data, tmp_path):
    clean_clam, clam_out = clamav_scan_file(tmp_path)
    heur_verdict, heur_info = heuristic_scan(filename, data)
    if not clean_clam or heur_verdict == "malicious":
        return False, f"ClamAV or heuristic flagged: {heur_info}\n{clam_out}"
    if heur_verdict == "suspicious":
        return False, f"Heuristic suspicious: {heur_info}"
    return True, f"Clean: {heur_info}\n{clam_out}"

# --------- Encryption ----------
def aes_encrypt_bytes(plain_bytes):
    key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plain_bytes)
    container = nonce + tag + ciphertext
    return container, key

def rsa_encrypt_key(aes_key: bytes, public_pem_path: str):
    with open(public_pem_path, "rb") as f:
        pub = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(pub)
    return cipher_rsa.encrypt(aes_key)

# --------- Flask Routes ----------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/authorize")
def authorize():
    if not os.path.exists(CREDENTIALS_FILE):
        return f"Place {CREDENTIALS_FILE} in project folder.", 500
    flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
    creds = flow.run_local_server(port=0)
    with open(TOKEN_FILE, "wb") as f:
        pickle.dump(creds, f)
    return "Authorization complete. Close this tab and return to the app."

@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return "No file uploaded", 400
    file = request.files["file"]
    if file.filename == "":
        return "No file selected", 400

    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp_path = tmp.name
    file.save(tmp_path)
    tmp.close()

    with open(tmp_path, "rb") as f:
        data = f.read()

    clean, scan_output = full_scan(file.filename, data, tmp_path)
    os.remove(tmp_path)

    if not clean:
        return f"❌ Upload blocked — {scan_output}", 400

    enc_container, aes_key = aes_encrypt_bytes(data)
    if not os.path.exists(RSA_PUBLIC_PEM):
        return f"Missing {RSA_PUBLIC_PEM}", 500
    enc_key = rsa_encrypt_key(aes_key, RSA_PUBLIC_PEM)

    try:
        service = get_drive_service()
    except Exception as e:
        return f"Drive auth error: {e}", 500

    bio = io.BytesIO(enc_container)
    media = MediaIoBaseUpload(bio, mimetype="application/octet-stream", resumable=True)
    fmeta = {"name": file.filename + ".enc"}
    uploaded = service.files().create(body=fmeta, media_body=media, fields="id,name").execute()

    bio2 = io.BytesIO(enc_key)
    media2 = MediaIoBaseUpload(bio2, mimetype="application/octet-stream", resumable=True)
    kmeta = {"name": file.filename + ".key.enc"}
    uploaded_key = service.files().create(body=kmeta, media_body=media2, fields="id,name").execute()

    return {
        "message": "✅ Scanned (ClamAV + heuristic), encrypted, and uploaded.",
        "file": uploaded.get("name"),
        "file_id": uploaded.get("id"),
        "key_file": uploaded_key.get("name"),
        "key_id": uploaded_key.get("id"),
        "scan_result": scan_output
    }

@app.route("/decrypt", methods=["POST"])
def decrypt():
    if "encfile" not in request.files or "keyfile" not in request.files or "private" not in request.files:
        return "Please upload encfile, keyfile and private.pem", 400
    encfile_obj = request.files["encfile"]
    keyfile = request.files["keyfile"].read()
    private_pem = request.files["private"].read()

    priv = RSA.import_key(private_pem)
    cipher_rsa = PKCS1_OAEP.new(priv)
    aes_key = cipher_rsa.decrypt(keyfile)

    encfile = encfile_obj.read()
    nonce, tag = encfile[:12], encfile[12:28]
    ciphertext = encfile[28:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plain = cipher.decrypt_and_verify(ciphertext, tag)
    original_filename = encfile_obj.filename.replace(".enc", "")
    return send_file(io.BytesIO(plain), as_attachment=True, download_name=original_filename)

# --------- Run ----------
if __name__ == "__main__":
    if not os.path.exists(CREDENTIALS_FILE):
        print(f"⚠️ Place {CREDENTIALS_FILE} in project folder.")
        raise SystemExit(1)
    port = get_free_port()
    print(f"🚀 Running Flask app on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=True)
