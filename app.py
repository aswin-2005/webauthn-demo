from flask import Flask, render_template, request, jsonify, session
import os, base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PORT=5000

app = Flask(__name__)
app.secret_key = os.urandom(32)

# In-memory store for demo
user_store = {}
SECRET = "🎯 Top Secret Content: Only Authenticated Users Can See This!"

def generate_challenge():
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("utf-8")

@app.route("/")
def index():
    return render_template("index.html")

# ---------------- Registration ----------------
@app.route("/register_request", methods=["POST"])
def register_request():
    challenge = generate_challenge()
    session["challenge"] = challenge
    return jsonify({
        "challenge": challenge,
        "user": {"id": "demo-user", "name": "Demo User", "displayName": "Demo User"}
    })

@app.route("/register_response", methods=["POST"])
def register_response():
    data = request.json
    public_key_pem = data["publicKeyPem"]
    user_store["public_key"] = public_key_pem
    return jsonify({"status": "ok"})

# ---------------- Login / Auth ----------------
@app.route("/login_request", methods=["POST"])
def login_request():
    challenge = generate_challenge()
    session["challenge"] = challenge
    return jsonify({"challenge": challenge})

@app.route("/login_response", methods=["POST"])
def login_response():
    data = request.json
    public_key_pem = user_store.get("public_key")
    if not public_key_pem:
        return jsonify({"status": "fail", "error": "No registered device"}), 400

    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    challenge = base64.urlsafe_b64decode(session["challenge"] + "==")
    signature_bytes = bytes(data["signature"])

    try:
        public_key.verify(signature_bytes, challenge, ec.ECDSA(hashes.SHA256()))
        session["authenticated"] = True
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "fail", "error": str(e)}), 400

@app.route("/secret")
def secret():
    if session.get("authenticated"):
        return jsonify({"secret": SECRET})
    return jsonify({"error": "Unauthorized"}), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

