import hmac
import hashlib
import base64
import json
import time
import re
import requests
from functools import wraps
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import jwt as pyjwt
from flask import Flask, request, jsonify, render_template, redirect, url_for, make_response, abort

app = Flask(__name__)
app.secret_key = "millennium-puzzle-secret-2024"

FLAG = "SECURINETS{7h3_m1ll3nn1um_3y3_s33s_4ll_s3cr3ts}"

with open("keys/private.pem", "rb") as f:
    PRIVATE_KEY = f.read()
with open("keys/public.pem", "rb") as f:
    PUBLIC_KEY = f.read()

USERS = {
    "yugi":  {"password": "puzzle123", "role": "guest"},
    "kaiba": {"password": "blueeyes",  "role": "guest"},
    "joey":  {"password": "duelbuddy", "role": "guest"},
}

PEGASUS_PIN    = "7316"
rate_limit_store = {}

DUELISTS = [
    {"id": "1", "name": "Yugi Muto",          "deck": "Dark Magician",          "lp": 4000, "rank": "King of Games"},
    {"id": "2", "name": "Seto Kaiba",          "deck": "Blue-Eyes White Dragon", "lp": 4000, "rank": "Vice-Champion"},
    {"id": "3", "name": "Joey Wheeler",        "deck": "Red-Eyes Black Dragon",  "lp": 4000, "rank": "Runner-Up"},
    {"id": "4", "name": "Maximillion Pegasus", "deck": "Toon World",             "lp": 4000, "rank": "Creator"},
]

INTROSPECTION_RESPONSE = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "types": [
                {
                    "name": "Query", "kind": "OBJECT",
                    "fields": [
                        {"name": "duelists",
                         "description": "List all registered duelists",
                         "args": [],
                         "type": {"kind": "LIST", "ofType": {"name": "Duelist"}}},
                        {"name": "getDuelistById",
                         "description": "Fetch a single duelist by ID",
                         "args": [{"name": "id", "type": {"name": "ID"}}],
                         "type": {"name": "Duelist"}},
                        {"name": "checkPegasusVault",
                         "description": "Attempt to unlock the Pegasus vault with the 4-digit Millennium code",
                         "args": [{"name": "pin", "type": {"name": "String"}}],
                         "type": {"name": "VaultResult"}}
                    ]
                },
                {"name": "Duelist",     "kind": "OBJECT",
                 "fields": [{"name":"id"},{"name":"name"},{"name":"deck"},{"name":"lp"},{"name":"rank"}]},
                {"name": "VaultResult", "kind": "OBJECT",
                 "fields": [{"name":"success"},{"name":"message"}]}
            ]
        }
    }
}

# ─── JWT helpers ──────────────────────────────────────────────────────────────

def _b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def create_token(username, role):
    """Sign with RS256 using private key."""
    payload = {
        "user": username,
        "role": role,
        "alg_note": "secured with academy asymmetric protocol",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    return pyjwt.encode(payload, PRIVATE_KEY, algorithm="RS256")

def decode_token(token):
    """
    VULNERABILITY: accepts both RS256 and HS256.
    When HS256 is used, verifies with public key as HMAC secret (raw bytes).
    Attacker who knows the public key can forge any payload.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_raw = json.loads(_b64url_decode(parts[0]))
        alg = header_raw.get("alg", "RS256")

        if alg == "HS256":
            # Verify HMAC-SHA256 using the public key bytes as secret
            signing_input = f"{parts[0]}.{parts[1]}".encode()
            expected_sig  = hmac.new(PUBLIC_KEY, signing_input, hashlib.sha256).digest()
            actual_sig    = _b64url_decode(parts[2])
            if not hmac.compare_digest(expected_sig, actual_sig):
                return None
            payload = json.loads(_b64url_decode(parts[1]))
            # Basic expiry check (skip if exp is huge sentinel value)
            exp = payload.get("exp", 0)
            if exp < int(time.time()) and exp < 9000000000:
                return None
            return payload

        elif alg == "RS256":
            return pyjwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])

        return None
    except Exception:
        return None

def get_current_user():
    token = request.cookies.get("session_token")
    return decode_token(token) if token else None

ROLE_ORDER = ["guest", "archivist", "pegasus"]

def require_role(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for("login"))
            if ROLE_ORDER.index(user.get("role", "guest")) < ROLE_ORDER.index(role):
                return render_template("forbidden.html", user=user), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ─── GraphQL executor ─────────────────────────────────────────────────────────

def execute_graphql(operation, client_ip, is_batch):
    query = operation.get("query", "")

    if "__schema" in query or "__typename" in query:
        return INTROSPECTION_RESPONSE

    errors = []
    data   = {}

    if re.search(r'\bduelists\b', query) and "getDuelistById" not in query and "checkPegasusVault" not in query:
        data["duelists"] = DUELISTS

    elif "getDuelistById" in query:
        m = re.search(r'getDuelistById\s*\(\s*id\s*:\s*["\']?(\w+)["\']?\s*\)', query)
        if m:
            found = next((d for d in DUELISTS if d["id"] == m.group(1)), None)
            data["getDuelistById"] = found
        else:
            errors.append({"message": "getDuelistById requires an id argument"})

    elif "checkPegasusVault" in query:
        m = re.search(r'checkPegasusVault\s*\(\s*pin\s*:\s*["\']?(\d+)["\']?\s*\)', query)
        if not m:
            errors.append({"message": "checkPegasusVault requires a pin argument (4-digit string)"})
        else:
            pin = m.group(1)
            # VULNERABILITY: batch requests skip rate limiting
            if not is_batch:
                now  = time.time()
                last = rate_limit_store.get(client_ip, 0)
                if (now - last) < 2.0:
                    return {"data": {"checkPegasusVault": {
                        "success": False,
                        "message": "Too many attempts! The Millennium Eye watches you. Wait before trying again."
                    }}}
                rate_limit_store[client_ip] = now

            if pin == PEGASUS_PIN:
                # "seal" field is a base64-encoded JSON object.
                # Pro players who decode it find:
                #   {"identity":"pegasus","directive":"assume this identity to enter the sanctum"}
                # This is the only place the pegasus role is revealed.
                data["checkPegasusVault"] = {
                    "success": True,
                    "message": "The code is correct. The seal of the Creator is broken.",
                    "seal":    "eyJpZGVudGl0eSI6ICJwZWdhc3VzIiwgImRpcmVjdGl2ZSI6ICJhc3N1bWUgdGhpcyBpZGVudGl0eSB0byBlbnRlciB0aGUgc2FuY3R1bSJ9"
                }
            else:
                data["checkPegasusVault"] = {
                    "success": False,
                    "message": "The Millennium Eye rejects your offering. That is not the sacred code."
                }
    else:
        errors.append({"message": "Unknown operation. Run introspection to discover available queries."})

    resp = {"data": data}
    if errors:
        resp["errors"] = errors
    return resp

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", user=get_current_user())

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        if username in USERS and USERS[username]["password"] == password:
            token = create_token(username, USERS[username]["role"])
            resp  = make_response(redirect(url_for("profile")))
            # samesite=None + secure=True so the cookie works when hosted behind
            # a reverse proxy / CDN (Render, Railway, etc.) over HTTPS.
            # Falls back gracefully on plain HTTP (localhost).
            is_https = request.is_secure or request.headers.get("X-Forwarded-Proto") == "https"
            resp.set_cookie(
                "session_token", token,
                httponly=True,
                samesite="None" if is_https else "Lax",
                secure=is_https,
            )
            return resp
        error = "Invalid credentials. The Shadow Realm claims the unworthy."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie("session_token")
    return resp

@app.route("/profile")
@require_role("guest")
def profile():
    return render_template("profile.html", user=get_current_user())

@app.route("/archive")
@require_role("archivist")
def archive():
    return render_template("archive.html", user=get_current_user())

@app.route("/pegasus")
@require_role("pegasus")
def pegasus_sanctum():
    return render_template("pegasus.html", user=get_current_user())

@app.route("/export/pdf", methods=["GET", "POST"])
@require_role("pegasus")
def export_pdf():
    user   = get_current_user()
    result = None
    error  = None
    if request.method == "POST":
        template_url = request.form.get("template_url", "").strip()
        if not template_url:
            error = "No URL provided."
        else:
            try:
                # VULNERABILITY: SSRF — fetches any URL without validation
                r      = requests.get(template_url, timeout=5)
                result = r.text
            except requests.exceptions.Timeout:
                error = "The Shadow Realm swallowed your request. Connection timed out."
            except Exception as e:
                error = f"Render failed: {str(e)}"
    return render_template("export.html", user=user, result=result, error=error)

@app.route("/internal/vault")
def internal_vault():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        abort(403)
    return f"""<!DOCTYPE html><html>
<head><title>Millennium Vault</title></head>
<body style="background:#080610;color:#c9a84c;font-family:monospace;padding:3rem;line-height:2;">
<h1 style="color:#f0d080;">MILLENNIUM VAULT - CLASSIFIED</h1>
<p>ACCESS GRANTED - ACADEMY INTERNAL NETWORK CONFIRMED</p>
<hr style="border-color:#7a6028;margin:1.5rem 0"/>
<p>Pegasus's Final Secret:</p>
<pre style="font-size:1.5rem;color:#00ff88;border:1px solid #7a6028;padding:1rem;display:inline-block;">{FLAG}</pre>
<p style="color:#4a3e2a;font-size:0.85rem;margin-top:1.5rem;">Restricted to academy-local interface only.</p>
</body></html>"""

@app.route("/api/duel", methods=["GET", "POST"])
@require_role("archivist")
def graphql_endpoint():
    if request.method == "GET":
        return render_template("graphiql.html", user=get_current_user())
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"errors": [{"message": "Invalid or missing JSON body"}]}), 400
    client_ip = request.remote_addr
    if isinstance(data, list):
        # VULNERABILITY: batch bypasses per-query rate limiting
        return jsonify([execute_graphql(op, client_ip, is_batch=True) for op in data])
    return jsonify(execute_graphql(data, client_ip, is_batch=False))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
