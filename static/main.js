const output = document.getElementById("output");
function log(msg) { output.textContent += msg + "\n"; }

// Base64URL -> Uint8Array
function base64urlToUint8Array(base64url) {
    const padding = '='.repeat((4 - base64url.length % 4) % 4);
    const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(base64);
    return Uint8Array.from([...raw].map(c => c.charCodeAt(0)));
}

// ---------- Register ----------
document.getElementById("registerBtn").onclick = async () => {
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
            authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
            timeout: 60000
        }
    });

    // Store rawId as PEM-like string for demo
    const publicKeyPem = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));

    await fetch("/register_response", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ publicKeyPem })
    });
    log("Device registered!");
};

// ---------- Login ----------
document.getElementById("loginBtn").onclick = async () => {
    log("Starting login...");
    const loginReq = await fetch("/login_request", { method: "POST" }).then(r => r.json());

    const assertion = await navigator.credentials.get({
        publicKey: {
            challenge: base64urlToUint8Array(loginReq.challenge),
            allowCredentials: [],
            userVerification: "required",
            timeout: 60000
        }
    });

    const signature = new Uint8Array(assertion.response.signature || assertion.response.authenticatorData || []);
    const res = await fetch("/login_response", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ signature: Array.from(signature) })
    }).then(r => r.json());

    log("Login result: " + JSON.stringify(res));
};

// ---------- Get Secret ----------
document.getElementById("getSecretBtn").onclick = async () => {
    const res = await fetch("/secret").then(r => r.json());
    log("Secret: " + JSON.stringify(res));
};
