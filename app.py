from flask import Flask, render_template, request, jsonify, session
import os, base64, cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

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
    print("Generated challenge for registration:", challenge)
    return jsonify({
        "challenge": challenge,
        "user": {"id": "demo-user", "name": "Demo User", "displayName": "Demo User"}
    })

@app.route("/register_response", methods=["POST"])
def register_response():
    data = request.json
    
    # Decode the attestation object
    attestation_object = base64.b64decode(data["attestationObject"])
    att_dict = cbor2.loads(attestation_object)
    
    # Extract the public key from authData
    auth_data = att_dict["authData"]
    
    # Parse authenticator data to get credential public key
    # authData structure: rpIdHash(32) + flags(1) + signCount(4) + attestedCredentialData
    attested_cred_data_start = 37
    
    # aaguid(16) + credentialIdLength(2) + credentialId(L) + credentialPublicKey
    aaguid = auth_data[attested_cred_data_start:attested_cred_data_start+16]
    cred_id_len = int.from_bytes(auth_data[attested_cred_data_start+16:attested_cred_data_start+18], 'big')
    credential_id_start = attested_cred_data_start + 18
    credential_id = auth_data[credential_id_start:credential_id_start+cred_id_len]
    
    # Public key is CBOR encoded after credential ID
    public_key_cbor = auth_data[credential_id_start+cred_id_len:]
    public_key_dict = cbor2.loads(public_key_cbor)
    
    # Store credential ID and public key coordinates
    user_store["credential_id"] = base64.b64encode(credential_id).decode()
    user_store["public_key"] = public_key_dict
    
    print("Stored credential for user")
    print("Credential ID:", user_store["credential_id"])
    
    return jsonify({"status": "ok"})

# ---------------- Login / Auth ----------------
@app.route("/login_request", methods=["POST"])
def login_request():
    challenge = generate_challenge()
    session["challenge"] = challenge
    print("Generated challenge for login:", challenge)
    
    # Return credential ID so client can use it
    cred_id = user_store.get("credential_id", "")
    return jsonify({
        "challenge": challenge,
        "credentialId": cred_id
    })

@app.route("/login_response", methods=["POST"])
def login_response():
    data = request.json
    
    if "public_key" not in user_store:
        return jsonify({"status": "fail", "error": "No registered device"}), 400
    
    print("Verifying signature...")
    
    # Reconstruct the public key from stored coordinates
    public_key_dict = user_store["public_key"]
    
    # For ES256 (COSE algorithm -7)
    # public_key_dict: {1: 2, 3: -7, -1: 1, -2: x_coord, -3: y_coord}
    x = public_key_dict[-2]
    y = public_key_dict[-3]
    
    # Create EC public key
    public_numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, 'big'),
        int.from_bytes(y, 'big'),
        ec.SECP256R1()
    )
    public_key = public_numbers.public_key(default_backend())
    
    # Get challenge and authenticator data
    challenge = base64.urlsafe_b64decode(session["challenge"] + "==")
    authenticator_data = bytes(data["authenticatorData"])
    client_data_json = bytes(data["clientDataJSON"])
    signature_bytes = bytes(data["signature"])
    
    # Create the signed data: authenticatorData + SHA256(clientDataJSON)
    client_data_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    client_data_hash.update(client_data_json)
    client_data_hash_bytes = client_data_hash.finalize()
    
    signed_data = authenticator_data + client_data_hash_bytes
    
    try:
        public_key.verify(signature_bytes, signed_data, ec.ECDSA(hashes.SHA256()))
        session["authenticated"] = True
        print("✓ Signature verified!")
        return jsonify({"status": "ok"})
    except Exception as e:
        print(f"✗ Verification failed: {e}")
        return jsonify({"status": "fail", "error": str(e)}), 400

@app.route("/secret")
def secret():
    if session.get("authenticated"):
        return jsonify({"secret": SECRET})
    return jsonify({"error": "Unauthorized"}), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)