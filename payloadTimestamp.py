# webhook_receiver.py
from flask import Flask, request, abort, jsonify
import hmac
import hashlib
import json
import time
import os

app = Flask(__name__)

# Configure these from environment in production
HUB_SECRET = os.environ.get("HUB_SECRET", "supersecretkey")        # bytes for HMAC verification
SIG_KEY = os.environ.get("SIG_KEY", "yoursignaturekey")           # alternative signature key (string)
MAX_TIMESTAMP_DRIFT = 10 * 60  # 10 minutes

LOG_FILE = os.environ.get("PAYLOAD_LOG", "/var/log/webhook/payload_log.txt")

def ensure_log_dir():
    logdir = os.path.dirname(LOG_FILE)
    if logdir and not os.path.exists(logdir):
        os.makedirs(logdir, exist_ok=True)

def write_log(entry: dict):
    ensure_log_dir()
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def process_data(data: dict):
    # TODO: Extend this function to trigger your deploy script, test runner, etc.
    # This stub simply logs the fact we've processed the data.
    write_log({"processed_at": int(time.time()), "note": "processed_payload", "payload_summary": {"keys": list(data.keys())}})

@app.route("/webhook", methods=["POST"])
def receiver():
    # 1) Subscription confirmation header (some providers use this)
    hook_secret = request.headers.get("X-Hook-Secret")
    if hook_secret:
        # Echo back for verification (Bitbucket-like pattern)
        response = jsonify({"status": "confirmed"})
        response.headers["X-Hook-Secret"] = hook_secret
        return response, 200

    payload_raw = request.get_data()  # bytes
    content_type = request.headers.get("Content-Type", "")

    # 2) GitHub-style HMAC signature verification (X-Hub-Signature-256)
    sig256 = request.headers.get("X-Hub-Signature-256")
    if sig256:
        try:
            sha_name, signature = sig256.split("=", 1)
        except ValueError:
            abort(400, "Bad signature header format")
        if sha_name != "sha256":
            abort(400, "Unsupported hash algorithm")
        mac = hmac.new(HUB_SECRET.encode("utf-8"), msg=payload_raw, digestmod=hashlib.sha256)
        if not hmac.compare_digest(mac.hexdigest(), signature):
            abort(403, "Invalid signature")
        # authorized, parse json
        try:
            payload = request.get_json(force=True)
        except Exception:
            payload = {"raw": payload_raw.decode("utf-8", errors="replace")}
        entry = {
            "received_at": int(time.time()),
            "event_type": request.headers.get("X-Event-Type", "unknown"),
            "auth": "hub-sha256",
            "payload": payload
        }
        write_log(entry)
        process_data(payload)
        return "OK", 200

    # 3) Fallback custom signature format: X-Hook-Signature -> "timestamp.signaturehex"
    sig_header = request.headers.get("X-Hook-Signature")
    if sig_header:
        try:
            timestamp_str, sig_received = sig_header.split(".", 1)
            timestamp = int(timestamp_str)
        except Exception:
            abort(400, "Bad X-Hook-Signature format")
        # validate timestamp freshness
        now = int(time.time())
        if abs(now - timestamp) > MAX_TIMESTAMP_DRIFT:
            abort(400, "Timestamp too old or in future")
        # calculate hmac using SIG_KEY
        mac = hmac.new(SIG_KEY.encode("utf-8"), msg=payload_raw, digestmod=hashlib.sha256)
        if not hmac.compare_digest(mac.hexdigest(), sig_received):
            abort(403, "Invalid signature")
        # authorized
        try:
            payload = request.get_json(force=True)
        except Exception:
            payload = {"raw": payload_raw.decode("utf-8", errors="replace")}
        entry = {
            "received_at": int(time.time()), 
            "auth": "custom-sig",
            "timestamp_header": timestamp,
            "payload": payload
        }
        write_log(entry)
        process_data(payload)
        return "OK", 200

    # no known verification headers
    abort(400, "No verification headers found")

if __name__ == "__main__":
    # For production run with a WSGI server (gunicorn) and systemd; debug only local
    app.run(host="0.0.0.0", port=5000, debug=False)
