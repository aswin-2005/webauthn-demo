const output = document.getElementById("output");
function log(msg) { output.textContent += msg + "\n"; }

// Base64URL -> Uint8Array
function base64urlToUint8Array(base64url) {
    const padding = '='.repeat((4 - base64url.length % 4) % 4);
    const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(base64);
    return Uint8Array.from([...raw].map(c => c.charCodeAt(0)));
}

// Uint8Array -> Base64
function arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

// ---------- Register ----------
document.getElementById("registerBtn").onclick = async () => {
    try {
        log("Starting registration...");
        const regReq = await fetch("/register_request", { method: "POST" }).then(r => r.json());

        const credential = await navigator.credentials.create({
            publicKey: {
                challenge: base64urlToUint8Array(regReq.challenge),
                rp: { name: "Demo Site" },
                user: {
                    id: new TextEncoder().encode(regReq.user.id),
                    name: regReq.user.name,
                    displayName: regReq.user.displayName
                },
                pubKeyCredParams: [
                    { type: "public-key", alg: -7 },    // ES256
                    { type: "public-key", alg: -257 }   // RS256
                ],
                authenticatorSelection: {
                    authenticatorAttachment: "platform",
                    userVerification: "required"
                },
                timeout: 60000,
                attestation: "direct"
            }
        });

        // Send the attestation object which contains the public key
        const response = {
            attestationObject: arrayBufferToBase64(credential.response.attestationObject),
            clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON)
        };

        await fetch("/register_response", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(response)
        });

        log("✓ Device registered successfully!");
    } catch (error) {
        log("✗ Registration failed: " + error.message);
    }
};

// ---------- Login ----------
document.getElementById("loginBtn").onclick = async () => {
    try {
        log("Starting login...");
        const loginReq = await fetch("/login_request", { method: "POST" }).then(r => r.json());

        const allowCredentials = loginReq.credentialId ? [{
            type: "public-key",
            id: base64urlToUint8Array(loginReq.credentialId)
        }] : [];

        const assertion = await navigator.credentials.get({
            publicKey: {
                challenge: base64urlToUint8Array(loginReq.challenge),
                allowCredentials: allowCredentials,
                userVerification: "required",
                timeout: 60000
            }
        });

        const loginData = {
            authenticatorData: Array.from(new Uint8Array(assertion.response.authenticatorData)),
            clientDataJSON: Array.from(new Uint8Array(assertion.response.clientDataJSON)),
            signature: Array.from(new Uint8Array(assertion.response.signature))
        };

        const res = await fetch("/login_response", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(loginData)
        }).then(r => r.json());

        if (res.status === "ok") {
            log("✓ Login successful!");
        } else {
            log("✗ Login failed: " + res.error);
        }
    } catch (error) {
        log("✗ Login failed: " + error.message);
    }
};

// ---------- Get Secret ----------
document.getElementById("getSecretBtn").onclick = async () => {
    try {
        const res = await fetch("/secret").then(r => r.json());
        if (res.secret) {
            log("✓ Secret retrieved: " + res.secret);
        } else {
            log("✗ " + res.error);
        }
    } catch (error) {
        log("✗ Failed to get secret: " + error.message);
    }
};