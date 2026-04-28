from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
import json
import os
import uuid
import io
import csv
from datetime import datetime
from werkzeug.utils import secure_filename
import networkx as nx

"""
Aegis-IAM Dashboard — Production Refactor
- Awaiting Data startup (no auto demo)
- Manual "Initialize Simulation" loads demo dataset
- Robust JSON ingestion:
  - Simple schema: users/roles/permissions/inherits
  - AWS IAM get-account-authorization-details (nested, managed + inline)
- Privilege escalation detection via graph traversal
- Case-insensitive MITRE ATT&CK mapping
- Over-privileged detection (wildcard, AdministratorAccess, iam:*, dangerous IAM/STS verbs)
- Separation-of-Duties conflict matrix (write + read/audit on self, etc.)
- Dynamic remediation playbooks + client-side PDF export
- Owned and Developed by Nisarg Chasmawala (Shroff), Jatin Kumar, and Santhakumar Parivalla.
"""

app = Flask(__name__)

# ---------------------------
# Security configuration
# ---------------------------
_DEFAULT_DEV_KEY = "dev-secret-change-me"
_secret = os.environ.get("AEGIS_SECRET_KEY", "")
if not _secret:
    # In dev only, fall back to a per-process random secret so sessions still
    # work without env var. Production deployments MUST set AEGIS_SECRET_KEY.
    import secrets as _secrets
    _secret = _secrets.token_hex(32)
app.secret_key = _secret

# Hardened session cookie
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("AEGIS_FORCE_HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 4,  # 4 hours
)
# Whether the app is behind HTTPS (controls HSTS + Secure cookie flag)
FORCE_HTTPS = os.environ.get("AEGIS_FORCE_HTTPS", "0") == "1"

APP_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(APP_DIR, "uploads")
DATA_DIR = os.path.join(APP_DIR, "data")
MITRE_MAP_FILE = os.path.join(APP_DIR, "mitre_map.json")

# ---------------------------
# Simulation registry
# Each entry surfaces in the UI so users can preview different attack postures.
# Keys are stable IDs (a-z0-9_), values are { file, label, description, severity }.
# ---------------------------
SIMULATIONS = {
    "demo": {
        "file": os.path.join(DATA_DIR, "demo_aws_auth_details.json"),
        "label": "Quick Demo",
        "description": "Minimal AWS export — single escalation, ideal first look.",
        "severity": "Low",
    },
    "realworld": {
        "file": os.path.join(DATA_DIR, "sample_aws_realworld.json"),
        "label": "Real-World AWS",
        "description": "5 users · 4 roles · federated SAML · NotAction · cross-account trust.",
        "severity": "High",
    },
    "compromised": {
        "file": os.path.join(DATA_DIR, "sim_compromised_account.json"),
        "label": "Compromised Account",
        "description": "Active attacker establishing persistence via access keys + backdoor role.",
        "severity": "Critical",
    },
    "insider": {
        "file": os.path.join(DATA_DIR, "sim_insider_threat.json"),
        "label": "Insider Threat",
        "description": "Veteran employee accumulated dangerous read+write over years.",
        "severity": "High",
    },
    "lambda_privesc": {
        "file": os.path.join(DATA_DIR, "sim_lambda_privesc.json"),
        "label": "Lambda PrivEsc",
        "description": "Classic AWS escalation — PassRole + Lambda/EC2 service inheritance.",
        "severity": "Critical",
    },
    "federated": {
        "file": os.path.join(DATA_DIR, "sim_federated_chaos.json"),
        "label": "Federated Chaos",
        "description": "Wildcard cross-account trust + loose OIDC sub claims + SAML admin.",
        "severity": "High",
    },
    "hardened": {
        "file": os.path.join(DATA_DIR, "sim_hardened_baseline.json"),
        "label": "Hardened Baseline",
        "description": "Properly scoped least-privilege — should score A+.",
        "severity": "None",
    },
}
# Back-compat alias
DEMO_FILE = SIMULATIONS["demo"]["file"]

os.makedirs(UPLOAD_DIR, exist_ok=True)

# Defense-in-depth upload limit
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB

# ---------------------------
# Risk constants (lowercase — matched case-insensitively)
# ---------------------------
ADMIN_ACTIONS = {"*", "iam:*"}
DANGEROUS_ACTIONS = {
    "sts:assumerole",
    "sts:*",
    "iam:passrole",
    "iam:attachuserpolicy",
    "iam:putuserpolicy",
    "iam:attachrolepolicy",
    "iam:putrolepolicy",
    "iam:attachgrouppolicy",
    "iam:putgrouppolicy",
    "iam:createaccesskey",
    "iam:updateaccesskey",
    "iam:updateassumerolepolicy",
    "iam:addusertogroup",
    "iam:createloginprofile",
    "iam:updateloginprofile",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
}

# Separation-of-Duties conflict matrix.
# Each entry = (write_action, read_or_audit_action, human_label).
# Triggered when a single principal holds BOTH actions.
CONFLICT_MATRIX = [
    ("iam:putuserpolicy",         "iam:getuserpolicy",   "Self-policy write + read (audit bypass risk)"),
    ("iam:attachuserpolicy",      "iam:listpolicies",    "Policy attachment + policy enumeration"),
    ("iam:putrolepolicy",         "iam:getrolepolicy",   "Role policy write + read"),
    ("iam:updateassumerolepolicy","iam:listroles",       "Trust modification + role enumeration"),
    ("iam:createaccesskey",       "iam:listaccesskeys",  "Key creation + key enumeration"),
    ("iam:createuser",            "iam:listusers",       "User provisioning + user enumeration"),
]

# Policy ARN suffixes that signal admin-equivalent privilege.
ADMIN_POLICY_SUFFIXES = (
    "/administratoraccess",
    "/iamfullaccess",
    "/poweruseraccess",
)


# ---------------------------
# Security headers
# ---------------------------
@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-XSS-Protection"] = "1; mode=block"  # legacy browsers
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=(), "
        "usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
    )
    # CSP — explicit allowlist of CDN origins. 'unsafe-eval' is required by
    # Tailwind CDN's runtime config; 'unsafe-inline' is required for our inline
    # initialization scripts. We compensate via Jinja autoescape + tojson|safe.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
            "https://cdn.tailwindcss.com "
            "https://cdn.jsdelivr.net "
            "https://cdnjs.cloudflare.com "
            "https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' "
            "https://fonts.googleapis.com "
            "https://cdn.jsdelivr.net "
            "https://cdnjs.cloudflare.com; "
        "font-src 'self' data: "
            "https://fonts.gstatic.com "
            "https://cdnjs.cloudflare.com; "
        "img-src 'self' data: blob: "
            "https://capsule-render.vercel.app "
            "https://readme-typing-svg.herokuapp.com "
            "https://img.shields.io "
            "https://avatars.githubusercontent.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "object-src 'none'"
    )
    if FORCE_HTTPS:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


# ---------------------------
# Error handlers — keep HTML branded; never leak stack traces
# ---------------------------
@app.errorhandler(404)
def _err_404(e):
    flash("Page not found.")
    return redirect(url_for("home")), 302


@app.errorhandler(413)
def _err_413(e):
    flash("File too large. Maximum upload size is 2 MB.")
    return redirect(url_for("home")), 302


@app.errorhandler(429)
def _err_429(e):
    flash("Rate limit exceeded. Please try again in a moment.")
    return redirect(url_for("home")), 302


@app.errorhandler(500)
def _err_500(e):
    # Do NOT echo exception details to client — log only.
    app.logger.error("Server error: %s", e)
    flash("Internal error. The team has been notified.")
    return redirect(url_for("home")), 302


# ---------------------------
# CSRF protection (lightweight, no Flask-WTF dependency)
# ---------------------------
import secrets as _secrets_mod
import hmac as _hmac

CSRF_FIELD = "_csrf"
CSRF_SESSION_KEY = "_csrf_token"


def _ensure_csrf_token() -> str:
    tok = session.get(CSRF_SESSION_KEY)
    if not tok:
        tok = _secrets_mod.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = tok
    return tok


@app.context_processor
def _inject_csrf():
    """Make {{ csrf_token() }} available in every template."""
    return {"csrf_token": _ensure_csrf_token}


@app.before_request
def _enforce_csrf():
    # Only enforce on state-changing methods. Exempt: GETs, exports.
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    token = request.form.get(CSRF_FIELD) or request.headers.get("X-CSRF-Token", "")
    expected = session.get(CSRF_SESSION_KEY, "")
    # Constant-time compare to prevent timing oracles
    if not expected or not _hmac.compare_digest(str(token), str(expected)):
        flash("Security check failed. Please reload and try again.")
        return redirect(url_for("home"))


# ---------------------------
# JSON parse with depth-bomb protection
# ---------------------------
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 200_000  # rough upper bound for absurd trees


def _validate_json_depth(obj, _depth=0, _counter=None):
    """Walk a parsed JSON value, enforcing depth + node limits."""
    if _counter is None:
        _counter = [0]
    _counter[0] += 1
    if _counter[0] > MAX_JSON_NODES:
        raise ValueError("JSON has too many nodes (parsing aborted to prevent resource exhaustion)")
    if _depth > MAX_JSON_DEPTH:
        raise ValueError(f"JSON nesting exceeds {MAX_JSON_DEPTH} levels")
    if isinstance(obj, dict):
        for v in obj.values():
            _validate_json_depth(v, _depth + 1, _counter)
    elif isinstance(obj, list):
        for v in obj:
            _validate_json_depth(v, _depth + 1, _counter)


# ---------------------------
# Rate limiter (in-memory, per-IP, token bucket — survives single-process)
# ---------------------------
import time
import threading

_rate_lock = threading.Lock()
_rate_buckets: dict = {}   # ip -> (tokens, last_refill_ts)
_RATE_BUCKET_CAP = 30      # max requests
_RATE_REFILL_PER_SEC = 0.5 # tokens added per second (= 30 req / minute steady)


def _client_ip() -> str:
    # Prefer X-Forwarded-For first hop if behind a trusted proxy; fall back to remote_addr.
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def rate_limited(per_call: int = 1) -> bool:
    """Return True if request should be REJECTED."""
    ip = _client_ip()
    now = time.time()
    with _rate_lock:
        tokens, last = _rate_buckets.get(ip, (_RATE_BUCKET_CAP, now))
        # Refill
        elapsed = max(0.0, now - last)
        tokens = min(_RATE_BUCKET_CAP, tokens + elapsed * _RATE_REFILL_PER_SEC)
        if tokens < per_call:
            _rate_buckets[ip] = (tokens, now)
            return True
        tokens -= per_call
        _rate_buckets[ip] = (tokens, now)
        return False


# ---------------------------
# Helpers
# ---------------------------
def load_json_file(path: str) -> dict:
    # Defense: cap on-disk size before parsing (prevents huge-file DoS even
    # if Flask MAX_CONTENT_LENGTH is bypassed somehow).
    try:
        size = os.path.getsize(path)
    except OSError:
        raise ValueError("Cannot stat dataset file.")
    if size > 2 * 1024 * 1024:
        raise ValueError("Dataset exceeds 2 MB cap.")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    _validate_json_depth(data)
    return data


def load_mitre_map() -> dict:
    """Returns dict with lowercase keys for case-insensitive matching."""
    try:
        raw = load_json_file(MITRE_MAP_FILE)
    except Exception:
        return {}
    return {str(k).lower(): v for k, v in raw.items()}


def set_current_dataset(path: str, display_name: str):
    # If we're replacing an uploaded dataset with a new one, clean the prior file
    # from disk to prevent uploads/ growing unbounded over a session.
    prior = session.get("current_data_file")
    if prior and prior != path and prior.startswith(UPLOAD_DIR):
        try:
            if os.path.isfile(prior):
                os.remove(prior)
        except OSError:
            pass
    session["current_data_file"] = path
    session["dataset_name"] = display_name
    session["generated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def clear_current_dataset():
    # Delete any uploaded file we own; never touch DATA_DIR demo files.
    prior = session.get("current_data_file")
    if prior and prior.startswith(UPLOAD_DIR):
        try:
            if os.path.isfile(prior):
                os.remove(prior)
        except OSError:
            pass
    session.pop("current_data_file", None)
    session.pop("dataset_name", None)
    session.pop("generated_at", None)


def current_dataset_path():
    return session.get("current_data_file")


def state():
    return {
        "has_data": bool(current_dataset_path() and os.path.isfile(current_dataset_path())),
        "dataset_name": session.get("dataset_name", "N/A"),
        "generated_at": session.get("generated_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    }


def safe_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def lower_set(actions) -> set:
    """Normalize a set/list of actions to lowercase strings."""
    return {str(a).strip().lower() for a in (actions or [])}


# ---------------------------
# Schema detection
# ---------------------------
def is_simple_schema(data: dict) -> bool:
    return isinstance(data, dict) and "users" in data and "roles" in data


def is_aws_auth_details(data: dict) -> bool:
    return isinstance(data, dict) and (
        "UserDetailList" in data or "RoleDetailList" in data or "GroupDetailList" in data
    )


def validate_simple_schema(data: dict):
    if not isinstance(data.get("users"), list) or not isinstance(data.get("roles"), dict):
        return False, "Invalid schema. Expected: users(list), roles(object)."
    for u in data["users"]:
        if "name" not in u or "roles" not in u or not isinstance(u["roles"], list):
            return False, "Each user must contain: name + roles(list)."
    for role, details in data["roles"].items():
        if "permissions" not in details or "inherits" not in details:
            return False, f"Role '{role}' must include permissions + inherits."
        if not isinstance(details["permissions"], list) or not isinstance(details["inherits"], list):
            return False, f"Role '{role}': permissions and inherits must be lists."
    return True, ""


# ---------------------------
# Policy parsing — case-insensitive, handles string + array forms
# ---------------------------
def extract_actions_from_statement(stmt: dict) -> set:
    """Pull Action / NotAction from one statement. NotAction logged as wildcard (broad-grant proxy)."""
    actions = set()
    if not isinstance(stmt, dict):
        return actions
    if str(stmt.get("Effect", "")).lower() != "allow":
        return actions
    if "Action" in stmt:
        for a in safe_list(stmt.get("Action")):
            actions.add(str(a).strip())
    # NotAction "Allow" is effectively wildcard except listed → treat as wildcard for risk.
    if "NotAction" in stmt:
        actions.add("*")
    return actions


def extract_actions_from_policy_doc(doc: dict) -> set:
    actions = set()
    if not isinstance(doc, dict):
        return actions
    for stmt in safe_list(doc.get("Statement", [])):
        actions |= extract_actions_from_statement(stmt)
    return actions


def aws_get_default_policy_doc(policy_obj: dict):
    if not isinstance(policy_obj, dict):
        return None
    for v in safe_list(policy_obj.get("PolicyVersionList", [])):
        if isinstance(v, dict) and v.get("IsDefaultVersion") is True and "Document" in v:
            return v.get("Document")
    return None


def aws_known_managed_policy_actions(policy_arn: str) -> set:
    """Heuristic mapping for common AWS managed policies (no API calls)."""
    arn = (policy_arn or "").lower()
    if arn.endswith("/administratoraccess"):
        return {"*"}
    if arn.endswith("/iamfullaccess"):
        return {"iam:*"}
    if arn.endswith("/poweruseraccess"):
        return {"*"}
    return set()


def is_admin_managed_policy(policy_arn: str) -> bool:
    arn = (policy_arn or "").lower()
    return any(arn.endswith(s) for s in ADMIN_POLICY_SUFFIXES)


def aws_extract_principal_arns(assume_doc: dict) -> set:
    arns = set()
    if not isinstance(assume_doc, dict):
        return arns
    for stmt in safe_list(assume_doc.get("Statement", [])):
        if not isinstance(stmt, dict):
            continue
        if str(stmt.get("Effect", "")).lower() != "allow":
            continue
        principal = stmt.get("Principal", {})
        if principal == "*" or principal == {"AWS": "*"}:
            arns.add("*")
            continue
        if isinstance(principal, dict) and "AWS" in principal:
            for p in safe_list(principal.get("AWS")):
                arns.add(str(p))
    return arns


# ---------------------------
# AWS ingestion -> normalized model
# ---------------------------
def parse_aws_auth_details(data: dict):
    policies = data.get("Policies", [])

    # Customer-managed policies -> embedded actions + admin flag
    customer_policy_actions = {}
    customer_policy_admin = {}
    for p in safe_list(policies):
        arn = p.get("Arn")
        doc = aws_get_default_policy_doc(p)
        acts = extract_actions_from_policy_doc(doc) if doc else set()
        if arn:
            customer_policy_actions[arn] = acts
            customer_policy_admin[arn] = ("*" in acts) or any(
                a.lower() == "iam:*" for a in acts
            )

    # Groups
    group_actions = {}
    group_admin_attachments = {}
    for g in safe_list(data.get("GroupDetailList", [])):
        gname = g.get("GroupName", "unknown_group")
        acts = set()
        admin_pols = []
        for inline in safe_list(g.get("GroupPolicyList", [])):
            acts |= extract_actions_from_policy_doc(inline.get("PolicyDocument", {}))
        for mp in safe_list(g.get("AttachedManagedPolicies", [])):
            arn = mp.get("PolicyArn")
            acts |= customer_policy_actions.get(arn, set())
            acts |= aws_known_managed_policy_actions(arn)
            if is_admin_managed_policy(arn) or customer_policy_admin.get(arn, False):
                admin_pols.append(mp.get("PolicyName", arn))
        group_actions[gname] = acts
        group_admin_attachments[gname] = admin_pols

    # Users
    users = []
    for u in safe_list(data.get("UserDetailList", [])):
        uname = u.get("UserName", "unknown_user")
        uarn = u.get("Arn", f"user:{uname}")
        acts = set()
        admin_pols = []
        for inline in safe_list(u.get("UserPolicyList", [])):
            acts |= extract_actions_from_policy_doc(inline.get("PolicyDocument", {}))
        for mp in safe_list(u.get("AttachedManagedPolicies", [])):
            arn = mp.get("PolicyArn")
            acts |= customer_policy_actions.get(arn, set())
            acts |= aws_known_managed_policy_actions(arn)
            if is_admin_managed_policy(arn) or customer_policy_admin.get(arn, False):
                admin_pols.append(mp.get("PolicyName", arn))
        for gname in safe_list(u.get("GroupList", [])):
            acts |= group_actions.get(gname, set())
            admin_pols.extend(group_admin_attachments.get(gname, []))
        users.append({
            "name": uname,
            "arn": uarn,
            "actions": acts,
            "admin_policies": sorted(set(admin_pols)),
        })

    # Roles
    roles = []
    for r in safe_list(data.get("RoleDetailList", [])):
        rname = r.get("RoleName", "unknown_role")
        rarn = r.get("Arn", f"role:{rname}")
        acts = set()
        admin_pols = []
        for inline in safe_list(r.get("RolePolicyList", [])):
            acts |= extract_actions_from_policy_doc(inline.get("PolicyDocument", {}))
        for mp in safe_list(r.get("AttachedManagedPolicies", [])):
            arn = mp.get("PolicyArn")
            acts |= customer_policy_actions.get(arn, set())
            acts |= aws_known_managed_policy_actions(arn)
            if is_admin_managed_policy(arn) or customer_policy_admin.get(arn, False):
                admin_pols.append(mp.get("PolicyName", arn))
        trust = aws_extract_principal_arns(r.get("AssumeRolePolicyDocument", {}))
        roles.append({
            "name": rname,
            "arn": rarn,
            "actions": acts,
            "trust": trust,
            "admin_policies": sorted(set(admin_pols)),
        })

    def is_admin_like(actions: set, admin_policies: list) -> bool:
        low = lower_set(actions)
        if low.intersection(ADMIN_ACTIONS):
            return True
        if "*" in actions:
            return True
        if admin_policies:
            return True
        return False

    admin_roles = {r["arn"] for r in roles if is_admin_like(r["actions"], r["admin_policies"])}

    principals = {u["arn"]: u for u in users}
    principals.update({r["arn"]: r for r in roles})

    def can_assume(actions: set) -> bool:
        low = lower_set(actions)
        return ("sts:assumerole" in low) or ("*" in actions) or ("sts:*" in low)

    assume_edges = []
    for p_arn, pobj in principals.items():
        if not can_assume(pobj.get("actions", set())):
            continue
        for role in roles:
            trust = role.get("trust", set())
            if "*" in trust or p_arn in trust:
                assume_edges.append({"from": p_arn, "to": role["arn"], "type": "can_assume"})

    return {
        "kind": "aws",
        "users": users,
        "roles": roles,
        "assume_edges": assume_edges,
        "admin_roles": admin_roles,
    }


def parse_simple_schema(data: dict):
    ok, msg = validate_simple_schema(data)
    if not ok:
        raise ValueError(msg)
    return {"kind": "simple", "raw": data}


def ingest_dataset(path: str):
    data = load_json_file(path)
    if is_simple_schema(data):
        return parse_simple_schema(data)
    if is_aws_auth_details(data):
        return parse_aws_auth_details(data)
    raise ValueError("Unsupported JSON format. Use the simple schema or AWS authorization-details export.")


# ---------------------------
# Analysis helpers
# ---------------------------
def severity_from_steps(steps: int) -> str:
    if steps <= 1:
        return "Critical"
    if steps == 2:
        return "High"
    if steps == 3:
        return "Medium"
    return "Low"


def mitre_tags(mitre_map: dict, permissions) -> list:
    """Case-insensitive MITRE mapping. Accepts set/list of permission strings."""
    tags = []
    seen = set()
    for p in sorted({str(x) for x in (permissions or [])}):
        key = p.lower()
        if key in mitre_map and key not in seen:
            t = mitre_map[key]
            tags.append({
                "permission": p,
                "technique": t.get("technique", ""),
                "id": t.get("id", ""),
                "tactic": t.get("tactic", ""),
                "note": t.get("note", ""),
            })
            seen.add(key)
    return tags


def overprivileged_reasons(actions: set, admin_policies: list) -> list:
    """Return human-readable reasons a principal is high-risk. Empty list = not flagged."""
    reasons = []
    low = lower_set(actions)

    if "*" in actions:
        reasons.append("Wildcard permissions detected: \"Action\": \"*\" grants unrestricted access.")
    if "iam:*" in low:
        reasons.append("Full IAM control detected (\"iam:*\") — can manipulate any identity.")
    if "sts:*" in low:
        reasons.append("Full STS access detected (\"sts:*\") — unrestricted role assumption.")
    if admin_policies:
        reasons.append(
            "Admin-equivalent managed policy attached: " + ", ".join(admin_policies)
        )

    dangerous_hits = sorted(low.intersection(DANGEROUS_ACTIONS) - {"*", "iam:*", "sts:*"})
    if dangerous_hits:
        reasons.append(
            "Dangerous IAM/STS verbs present: " + ", ".join(dangerous_hits)
        )
    return reasons


def sod_conflicts_for(actions: set) -> list:
    """Return list of conflict labels based on the configured matrix."""
    low = lower_set(actions)
    found = []
    for write_act, read_act, label in CONFLICT_MATRIX:
        if write_act in low and read_act in low:
            found.append({
                "label": label,
                "pair": [write_act, read_act],
            })
    return found


# ---------------------------
# MITRE ATT&CK Tactic Taxonomy (Enterprise — IAM-relevant subset)
# ---------------------------
ATTACK_TACTICS = [
    {"id": "TA0001", "name": "Initial Access",       "color": "#A78BFA"},
    {"id": "TA0002", "name": "Execution",            "color": "#C084FC"},
    {"id": "TA0003", "name": "Persistence",          "color": "#22D3EE"},
    {"id": "TA0004", "name": "Privilege Escalation", "color": "#FF355E"},
    {"id": "TA0005", "name": "Defense Evasion",      "color": "#FFB020"},
    {"id": "TA0006", "name": "Credential Access",    "color": "#F472B6"},
    {"id": "TA0007", "name": "Discovery",            "color": "#34D399"},
    {"id": "TA0008", "name": "Lateral Movement",     "color": "#60A5FA"},
    {"id": "TA0009", "name": "Collection",           "color": "#FCD34D"},
    {"id": "TA0040", "name": "Impact",               "color": "#F97316"},
]
TACTIC_NAME_TO_ID = {t["name"].lower(): t["id"] for t in ATTACK_TACTICS}


def severity_distribution(findings: list) -> dict:
    """Count findings per severity bucket — used for stat sparkline."""
    buckets = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity", "Low")
        if sev in buckets:
            buckets[sev] += 1
    return buckets


def compute_posture_score(findings: list, overprivileged: list, conflicts: list) -> dict:
    """Composite security-posture score 0–100 with letter grade and drivers.

    Weighting model (transparent — surfaced to UI for explainability):
      Critical escalation = -15
      High escalation     = -10
      Medium escalation   =  -6
      Low escalation      =  -3
      Over-privileged     =  -8 each
      SoD conflict        =  -5 each
    Floored at zero.
    """
    score = 100
    factors = []

    sev_counts = severity_distribution(findings)
    if sev_counts["Critical"]:
        delta = sev_counts["Critical"] * -15
        score += delta
        factors.append({"label": f"{sev_counts['Critical']} Critical escalation(s)", "delta": delta})
    if sev_counts["High"]:
        delta = sev_counts["High"] * -10
        score += delta
        factors.append({"label": f"{sev_counts['High']} High escalation(s)", "delta": delta})
    if sev_counts["Medium"]:
        delta = sev_counts["Medium"] * -6
        score += delta
        factors.append({"label": f"{sev_counts['Medium']} Medium escalation(s)", "delta": delta})
    if sev_counts["Low"]:
        delta = sev_counts["Low"] * -3
        score += delta
        factors.append({"label": f"{sev_counts['Low']} Low escalation(s)", "delta": delta})
    if overprivileged:
        delta = len(overprivileged) * -8
        score += delta
        factors.append({"label": f"{len(overprivileged)} Over-privileged principal(s)", "delta": delta})
    if conflicts:
        delta = len(conflicts) * -5
        score += delta
        factors.append({"label": f"{len(conflicts)} Separation-of-Duties conflict(s)", "delta": delta})

    score = max(0, min(100, score))

    if score >= 95:
        grade, color, status = "A+", "#32FF7E", "Hardened"
    elif score >= 85:
        grade, color, status = "A",  "#32FF7E", "Strong"
    elif score >= 70:
        grade, color, status = "B",  "#22D3EE", "Acceptable"
    elif score >= 50:
        grade, color, status = "C",  "#FFB020", "At Risk"
    elif score >= 30:
        grade, color, status = "D",  "#F97316", "Compromised Posture"
    else:
        grade, color, status = "F",  "#FF355E", "Critical Posture"

    return {
        "score": score,
        "grade": grade,
        "color": color,
        "status": status,
        "factors": factors,
        "severity_distribution": sev_counts,
    }


def compute_mitre_heatmap(findings: list, overprivileged: list, principals_actions: list = None, mitre_map: dict = None) -> list:
    """Return ATT&CK heatmap: per-tactic technique aggregation.

    Aggregates MITRE techniques from THREE sources so the matrix is never blind:
      1. Findings (escalation chains)
      2. Over-privileged principals
      3. EVERY principal's permissions (so dangerous verbs surface even when the
         principal isn't flagged as escalated or over-privileged — this is the
         common "real-world" case where IAM has dangerous verbs scoped tightly)

    Compound tactics like "Privilege Escalation / Persistence" are decomposed
    across both tactic rows. Returned in canonical tactic order.
    """
    bucket = {t["id"]: {
        "id": t["id"],
        "name": t["name"],
        "color": t["color"],
        "techniques": {},   # tech_id -> {id, name, count, principals:set}
    } for t in ATTACK_TACTICS}

    def absorb(item_mitre, principal):
        for t in item_mitre or []:
            tactic_field = (t.get("tactic") or "").strip()
            if not tactic_field:
                continue
            for tac_name in [s.strip() for s in tactic_field.split("/") if s.strip()]:
                tac_id = TACTIC_NAME_TO_ID.get(tac_name.lower())
                if not tac_id:
                    continue
                row = bucket[tac_id]
                tech_id = t.get("id") or "?"
                tech_name = t.get("technique") or "Unknown"
                key = f"{tech_id}::{tech_name}"
                if key not in row["techniques"]:
                    row["techniques"][key] = {
                        "id": tech_id,
                        "name": tech_name,
                        "count": 0,
                        "principals": set(),
                    }
                row["techniques"][key]["count"] += 1
                row["techniques"][key]["principals"].add(principal)

    # Source 1+2: findings & over-priv
    for f in findings:
        absorb(f.get("mitre"), f.get("principal", "?"))
    for u in overprivileged:
        absorb(u.get("mitre"), u.get("principal", "?"))

    # Source 3: EVERY principal's permissions (the fix for "MITRE not firing")
    if principals_actions and mitre_map:
        for entry in principals_actions:
            principal_label = entry.get("principal", "?")
            actions = entry.get("actions") or []
            tags = mitre_tags(mitre_map, actions)
            absorb(tags, principal_label)

    out = []
    for t in ATTACK_TACTICS:
        row = bucket[t["id"]]
        techs = []
        for v in row["techniques"].values():
            techs.append({
                "id": v["id"],
                "name": v["name"],
                "count": v["count"],
                "principals": sorted(v["principals"]),
            })
        techs.sort(key=lambda x: (-x["count"], x["id"]))
        total_principals = len({p for v in row["techniques"].values() for p in v["principals"]})
        out.append({
            "id": row["id"],
            "name": row["name"],
            "color": row["color"],
            "techniques": techs,
            "total_principals": total_principals,
            "intensity": min(4, len(techs)),  # 0..4 visual heat level
        })
    return out


def compute_diff(prev: dict, curr: dict) -> dict:
    """Per-stat delta vs previous analysis run."""
    if not prev:
        return {}
    keys = ["users", "roles", "policies", "escalations", "overprivileged", "conflicts", "risks"]
    return {k: curr.get(k, 0) - prev.get(k, 0) for k in keys}


def build_graph_and_findings(model: dict, mitre_map: dict):
    findings, overprivileged, conflicts = [], [], []

    # ---- Simple schema ----
    if model["kind"] == "simple":
        raw = model["raw"]
        G = nx.DiGraph()
        for role in raw["roles"].keys():
            G.add_node(role)
        for role, details in raw["roles"].items():
            for inh in details.get("inherits", []):
                G.add_edge(role, inh, label="inherits")

        TARGET_ROLE = "admin"
        for u in raw["users"]:
            uname = u.get("name", "unknown_user")
            for start_role in u.get("roles", []):
                if start_role not in G.nodes:
                    continue
                if nx.has_path(G, start_role, TARGET_ROLE):
                    path = nx.shortest_path(G, start_role, TARGET_ROLE)
                    steps = len(path) - 1
                    perms = set()
                    for r in path:
                        perms |= set(raw["roles"].get(r, {}).get("permissions", []))
                    findings.append({
                        "principal": uname,
                        "entry": start_role,
                        "chain": " → ".join(path),
                        "steps": steps,
                        "severity": severity_from_steps(steps),
                        "root_cause": "Role inheritance chain enables indirect admin access.",
                        "remediation_summary": "Break unsafe inheritance and enforce least privilege.",
                        "patch_steps": [
                            "Review and remove the inheritance edge that grants admin.",
                            "Split privileged permissions into a dedicated admin-only role.",
                            "Require approvals for role changes and audit role drift.",
                        ],
                        "strategy": [
                            "Adopt Just-In-Time elevation for admin actions.",
                            "Continuously monitor role changes; alert on privilege grants.",
                        ],
                        "mitre": mitre_tags(mitre_map, perms),
                    })
                    break

        # Over-privileged + SoD for simple schema (resolve permissions per user)
        for u in raw["users"]:
            uname = u.get("name", "unknown_user")
            user_perms = set()
            for r in u.get("roles", []):
                user_perms |= set(raw["roles"].get(r, {}).get("permissions", []))
            reasons = overprivileged_reasons(user_perms, [])
            if reasons:
                sample = ", ".join(sorted(list(user_perms))[:10]) or "(none)"
                overprivileged.append({
                    "principal": f"user:{uname}",
                    "permission_sample": sample,
                    "reasons": reasons,
                    "mitre": mitre_tags(mitre_map, user_perms),
                })
            sod = sod_conflicts_for(user_perms)
            if sod:
                conflicts.append({"principal": f"user:{uname}", "conflicts": sod})

        telemetry = {
            "users": len(raw.get("users", [])),
            "roles": len(raw.get("roles", {})),
            "policies": sum(len(v.get("permissions", [])) for v in raw.get("roles", {}).values()),
            "escalations": len(findings),
            "overprivileged": len(overprivileged),
            "conflicts": len(conflicts),
            "risks": len(findings) + len(overprivileged) + len(conflicts),
        }

        graph_payload = {"nodes": [], "edges": []}
        for role in raw["roles"].keys():
            graph_payload["nodes"].append({"id": f"role:{role}", "label": role, "group": "role", "title": f"Role: {role}"})
        for u in raw["users"]:
            uname = u.get("name", "unknown_user")
            graph_payload["nodes"].append({"id": f"user:{uname}", "label": uname, "group": "user", "title": f"User: {uname}"})
            for r in u.get("roles", []):
                graph_payload["edges"].append({"from": f"user:{uname}", "to": f"role:{r}", "label": "assigned", "arrows": "to"})
        for role, details in raw["roles"].items():
            for inh in details.get("inherits", []):
                graph_payload["edges"].append({"from": f"role:{role}", "to": f"role:{inh}", "label": "inherits", "arrows": "to"})

        # Surface every principal's effective permissions for heatmap aggregation.
        principals_actions = []
        for u in raw["users"]:
            uname = u.get("name", "unknown_user")
            user_perms_local = set()
            for r in u.get("roles", []):
                user_perms_local |= set(raw["roles"].get(r, {}).get("permissions", []))
            principals_actions.append({"principal": f"user:{uname}", "actions": list(user_perms_local)})
        for role_name, role_def in raw["roles"].items():
            principals_actions.append({"principal": f"role:{role_name}", "actions": list(role_def.get("permissions", []))})

        return findings, overprivileged, conflicts, telemetry, graph_payload, principals_actions

    # ---- AWS model ----
    user_arns = {u["arn"] for u in model["users"]}
    principals = {u["arn"]: f"user:{u['name']}" for u in model["users"]}
    principals.update({r["arn"]: f"role:{r['name']}" for r in model["roles"]})

    role_actions = {r["arn"]: r.get("actions", set()) for r in model["roles"]}
    role_trust = {r["arn"]: r.get("trust", set()) for r in model["roles"]}
    admin_roles = model.get("admin_roles", set())

    G = nx.DiGraph()
    for arn, label in principals.items():
        group = "user" if arn in user_arns else "role"
        G.add_node(arn, label=label, group=group)
    for e in model.get("assume_edges", []):
        G.add_edge(e["from"], e["to"], label="can_assume")

    # Escalation chains: user -> ... -> admin role
    for u in model["users"]:
        uarn = u["arn"]
        for target in admin_roles:
            if uarn in G.nodes and target in G.nodes and nx.has_path(G, uarn, target):
                path = nx.shortest_path(G, uarn, target)
                steps = len(path) - 1
                eff = set(u.get("actions", set())) | set(role_actions.get(target, set()))
                trust = role_trust.get(target, set())
                trust_is_wild = "*" in trust

                root_cause = "User can call sts:AssumeRole and the target role's trust policy permits that principal."
                if trust_is_wild:
                    root_cause = "Target role trust policy is wildcard — broad assume-role access."

                role_name = target.split("/")[-1] if "/" in target else target

                findings.append({
                    "principal": principals.get(uarn, uarn),
                    "entry": "AWS IAM User",
                    "chain": " → ".join([principals.get(x, x) for x in path]),
                    "steps": steps,
                    "severity": severity_from_steps(steps),
                    "root_cause": root_cause,
                    "remediation_summary": "Tighten trust policy + restrict assume permissions + remove admin policies from assumable roles.",
                    "patch_steps": [
                        f"aws iam list-attached-role-policies --role-name {role_name}",
                        f"aws iam detach-role-policy --role-name {role_name} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                        f"aws iam update-assume-role-policy --role-name {role_name} --policy-document file://tightened_trust.json",
                        f"aws iam put-role-permissions-boundary --role-name {role_name} --permissions-boundary arn:aws:iam::ACCOUNT:policy/BoundaryPolicy",
                    ],
                    "strategy": [
                        "Avoid attaching AdministratorAccess to roles assumable by non-admin users.",
                        "Require MFA + conditions for role assumption (aws:MultiFactorAuthPresent, source IP, session tags).",
                        "Use Permission Boundaries and/or SCPs to cap maximum privileges.",
                        "Alert on sts:AssumeRole and IAM policy changes in CloudTrail.",
                    ],
                    "mitre": mitre_tags(mitre_map, eff),
                })
                break

    # Over-privileged users (structured reasons)
    for u in model["users"]:
        reasons = overprivileged_reasons(u.get("actions", set()), u.get("admin_policies", []))
        if reasons:
            sample = ", ".join(sorted(list(u.get("actions", set())))[:10]) or "(none)"
            overprivileged.append({
                "principal": f"user:{u['name']}",
                "permission_sample": sample,
                "reasons": reasons,
                "mitre": mitre_tags(mitre_map, u.get("actions", set())),
            })

    # SoD conflicts (matrix)
    for u in model["users"]:
        sod = sod_conflicts_for(u.get("actions", set()))
        if sod:
            conflicts.append({"principal": f"user:{u['name']}", "conflicts": sod})

    telemetry = {
        "users": len(model.get("users", [])),
        "roles": len(model.get("roles", [])),
        "policies": sum(1 for u in model.get("users", []) if u.get("admin_policies"))
                  + sum(1 for r in model.get("roles", []) if r.get("admin_policies")),
        "escalations": len(findings),
        "overprivileged": len(overprivileged),
        "conflicts": len(conflicts),
        "risks": len(findings) + len(overprivileged) + len(conflicts),
    }

    graph_payload = {"nodes": [], "edges": []}
    for arn, label in principals.items():
        group = "user" if arn in user_arns else "role"
        graph_payload["nodes"].append({"id": arn, "label": label, "group": group, "title": f"{label}\nARN: {arn}"})
    for e in model.get("assume_edges", []):
        graph_payload["edges"].append({"from": e["from"], "to": e["to"], "label": "can_assume", "arrows": "to"})

    # Surface every principal's effective action set so the heatmap can light
    # up MITRE techniques even when the principal isn't flagged as escalated
    # or over-privileged. This is critical for real-world IAM exports.
    principals_actions = []
    for u in model.get("users", []):
        principals_actions.append({
            "principal": f"user:{u['name']}",
            "actions": list(u.get("actions", set())),
        })
    for r in model.get("roles", []):
        principals_actions.append({
            "principal": f"role:{r['name']}",
            "actions": list(r.get("actions", set())),
        })

    return findings, overprivileged, conflicts, telemetry, graph_payload, principals_actions


# ---------------------------
# Routes
# ---------------------------
@app.route("/", methods=["GET"])
def home():
    st = state()
    findings, overprivileged, conflicts = [], [], []
    telemetry = {"users": 0, "roles": 0, "policies": 0, "escalations": 0, "overprivileged": 0, "conflicts": 0, "risks": 0}
    posture = compute_posture_score([], [], [])
    heatmap = compute_mitre_heatmap([], [])
    diff = {}

    if st["has_data"]:
        try:
            model = ingest_dataset(current_dataset_path())
            mitre_map = load_mitre_map()
            findings, overprivileged, conflicts, telemetry, _, principals_actions = build_graph_and_findings(model, mitre_map)
            posture = compute_posture_score(findings, overprivileged, conflicts)
            heatmap = compute_mitre_heatmap(findings, overprivileged, principals_actions, mitre_map)
            diff = compute_diff(session.get("prev_telemetry", {}), telemetry)
            session["prev_telemetry"] = telemetry
        except Exception as e:
            flash(f"Analysis error: {e}")
            clear_current_dataset()
            st = state()

    # Pass simulations registry as a list (template-friendly)
    sim_list = [{"id": k, **v} for k, v in SIMULATIONS.items()]

    return render_template(
        "index.html",
        title="Aegis-IAM Dashboard",
        state=st,
        findings=findings,
        overprivileged=overprivileged,
        conflicts=conflicts,
        telemetry=telemetry,
        posture=posture,
        heatmap=heatmap,
        diff=diff,
        simulations=sim_list,
    )


@app.route("/api/export/json", methods=["GET"])
def export_json():
    """Stream the full intelligence payload as a JSON file download."""
    st = state()
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "dataset": st.get("dataset_name"),
        "telemetry": {},
        "posture": {},
        "findings": [],
        "overprivileged": [],
        "conflicts": [],
        "heatmap": [],
    }
    if st["has_data"]:
        try:
            model = ingest_dataset(current_dataset_path())
            mitre_map = load_mitre_map()
            findings, overpriv, conflicts, telemetry, _, principals_actions = build_graph_and_findings(model, mitre_map)
            payload["telemetry"] = telemetry
            payload["posture"] = compute_posture_score(findings, overpriv, conflicts)
            payload["findings"] = findings
            payload["overprivileged"] = overpriv
            payload["conflicts"] = conflicts
            payload["heatmap"] = compute_mitre_heatmap(findings, overpriv, principals_actions, mitre_map)
        except Exception as e:
            payload["error"] = str(e)

    body = json.dumps(payload, indent=2, default=str)
    return Response(
        body,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=aegis-iam-intelligence.json"},
    )


@app.route("/api/export/csv", methods=["GET"])
def export_csv():
    """Stream a flat CSV combining all findings, over-privileged, conflicts."""
    st = state()
    rows = []
    if st["has_data"]:
        try:
            model = ingest_dataset(current_dataset_path())
            mitre_map = load_mitre_map()
            findings, overpriv, conflicts, _, _, principals_actions = build_graph_and_findings(model, mitre_map)
            for f in findings:
                rows.append({
                    "type": "escalation",
                    "principal": f.get("principal", ""),
                    "severity": f.get("severity", ""),
                    "detail": f.get("chain", ""),
                    "root_cause": f.get("root_cause", ""),
                    "remediation": f.get("remediation_summary", ""),
                    "mitre": " | ".join(
                        f"{m.get('id','')} {m.get('technique','')}" for m in f.get("mitre", [])
                    ),
                })
            for u in overpriv:
                rows.append({
                    "type": "overprivileged",
                    "principal": u.get("principal", ""),
                    "severity": "High",
                    "detail": " ; ".join(u.get("reasons", [])),
                    "root_cause": "Excess permissions on principal",
                    "remediation": "Revoke wildcard / admin-equivalent permissions, apply least privilege",
                    "mitre": " | ".join(
                        f"{m.get('id','')} {m.get('technique','')}" for m in u.get("mitre", [])
                    ),
                })
            for c in conflicts:
                for item in c.get("conflicts", []):
                    rows.append({
                        "type": "sod_conflict",
                        "principal": c.get("principal", ""),
                        "severity": "Medium",
                        "detail": f"{item.get('label','')} ({' + '.join(item.get('pair', []))})",
                        "root_cause": "Single principal holds conflicting duties",
                        "remediation": "Split duties across principals; introduce approval boundary",
                        "mitre": "",
                    })
        except Exception:
            pass

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["type", "principal", "severity", "detail", "root_cause", "remediation", "mitre"])
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=aegis-iam-findings.csv"},
    )


@app.route("/upload", methods=["POST"])
def upload():
    if rate_limited(per_call=2):
        flash("Too many requests. Please slow down.")
        return redirect(url_for("home"))

    if "file" not in request.files:
        flash("No file provided.")
        return redirect(url_for("home"))

    f = request.files["file"]
    if not f.filename:
        flash("No selected file.")
        return redirect(url_for("home"))

    # Defense-in-depth: secure_filename strips path traversal; we re-check
    # extension AND that the resulting name is non-empty after sanitization.
    filename = secure_filename(f.filename)
    if not filename or not filename.lower().endswith(".json"):
        flash("Upload must be a .json file.")
        return redirect(url_for("home"))

    # Light MIME sniff — first non-whitespace byte must be '{' or '['
    head = f.stream.read(64)
    f.stream.seek(0)
    stripped = head.lstrip()
    if not stripped or stripped[:1] not in (b"{", b"["):
        flash("File does not appear to be valid JSON.")
        return redirect(url_for("home"))

    unique = f"{uuid.uuid4().hex[:10]}_{filename}"
    save_path = os.path.join(UPLOAD_DIR, unique)

    # Defense: realpath must stay inside UPLOAD_DIR (path-traversal proof)
    real_save = os.path.realpath(save_path)
    real_upload = os.path.realpath(UPLOAD_DIR)
    if not real_save.startswith(real_upload + os.sep):
        flash("Refused: path traversal attempt detected.")
        return redirect(url_for("home"))

    f.save(save_path)

    try:
        _ = ingest_dataset(save_path)  # validate/parse with depth + node guards
    except Exception as e:
        try:
            os.remove(save_path)
        except Exception:
            pass
        flash(f"Invalid dataset: {e}")
        return redirect(url_for("home"))

    set_current_dataset(save_path, filename)
    flash(f"Dataset loaded: {filename}")
    return redirect(url_for("home"))


@app.route("/init_demo", methods=["POST"])
def init_demo():
    # Allow caller to pick which simulation to load via 'sim' form field
    sim_id = (request.form.get("sim") or "demo").strip().lower()
    # Defense: only allow keys we know about (prevents path traversal via crafted form)
    sim = SIMULATIONS.get(sim_id)
    if not sim:
        flash(f"Unknown simulation: {sim_id}")
        return redirect(url_for("home"))
    if not os.path.isfile(sim["file"]):
        flash(f"Simulation file missing: {sim['label']}")
        return redirect(url_for("home"))
    set_current_dataset(sim["file"], os.path.basename(sim["file"]))
    flash(f"Simulation loaded: {sim['label']}")
    return redirect(url_for("home"))


@app.route("/reset", methods=["POST"])
def reset():
    clear_current_dataset()
    session.pop("prev_telemetry", None)
    flash("Reset complete. Awaiting data.")
    return redirect(url_for("home"))


@app.route("/graph", methods=["GET"])
def graph():
    st = state()
    payload = {"nodes": [], "edges": []}

    if st["has_data"]:
        try:
            model = ingest_dataset(current_dataset_path())
            mitre_map = load_mitre_map()
            _, _, _, _, payload, _ = build_graph_and_findings(model, mitre_map)
        except Exception as e:
            flash(f"Graph build error: {e}")

    return render_template("graph.html", title="Graph View", state=st, graph_payload=payload)


@app.route("/playbook", methods=["GET"])
def playbook():
    st = state()
    findings = []

    if st["has_data"]:
        try:
            model = ingest_dataset(current_dataset_path())
            mitre_map = load_mitre_map()
            findings, _, _, _, _, _ = build_graph_and_findings(model, mitre_map)
        except Exception as e:
            flash(f"Playbook error: {e}")

    return render_template("playbook.html", title="Dynamic Playbook", state=st, findings=findings)


@app.route("/intel", methods=["GET"])
def intel_lab():
    return render_template("intel_lab.html", title="Intel Retrieval Lab")


if __name__ == "__main__":
    # Production-safe defaults. Enable debug only via AEGIS_DEBUG=1.
    debug = os.environ.get("AEGIS_DEBUG", "0") == "1"
    port = int(os.environ.get("PORT", "5000"))
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(host=host, port=port, debug=debug)
