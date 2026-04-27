from flask import Flask, render_template, request, redirect, url_for, flash, session
import json
import os
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename
import networkx as nx

"""
Aegis-IAM Dashboard
- Clean startup: Awaiting Data (no auto demo)
- Manual "Initialize Simulation" loads demo file
- Robust JSON ingestion:
  - Simple schema: users/roles/permissions/inherits
  - AWS IAM get-account-authorization-details (nested)
- Privilege escalation detection via graph traversal
- Dynamic remediation playbooks + PDF export (client-side)
"""

app = Flask(__name__)
app.secret_key = os.environ.get("AEGIS_SECRET_KEY", "dev-secret-change-me")

APP_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(APP_DIR, "uploads")
DATA_DIR = os.path.join(APP_DIR, "data")
MITRE_MAP_FILE = os.path.join(APP_DIR, "mitre_map.json")
DEMO_FILE = os.path.join(DATA_DIR, "demo_aws_auth_details.json")

os.makedirs(UPLOAD_DIR, exist_ok=True)

# Upload limit (defense-in-depth)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB

ADMIN_ACTIONS = {"*", "iam:*"}
DANGEROUS_ACTIONS = {
    "sts:assumerole",
    "iam:passrole",
    "iam:attachuserpolicy",
    "iam:putuserpolicy",
    "iam:attachrolepolicy",
    "iam:putrolepolicy",
    "iam:createaccesskey",
    "iam:updateassumerolepolicy",
    "iam:addusertogroup",
    "iam:createloginprofile",
}

# Example separation-of-duties conflicts (edit as needed)
CONFLICT_PERMISSION_PAIRS = [
    ("iam:attachuserpolicy", "iam:listpolicies"),
    ("iam:putuserpolicy", "iam:listpolicies"),
    ("iam:updateassumerolepolicy", "iam:listroles"),
]


@app.after_request
def add_security_headers(resp):
    """Basic secure headers (OWASP-minded)."""
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    # Minimal CSP allowing CDN scripts for Chart.js, html2pdf, and vis-network
    resp.headers["Content-Security-Policy"] = "default-src 'self' https: 'unsafe-inline' 'unsafe-eval' data:;"
    return resp


def load_json_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_mitre_map() -> dict:
    """MITRE mapping is optional; tool still works if file is missing."""
    try:
        return load_json_file(MITRE_MAP_FILE)
    except Exception:
        return {}


def set_current_dataset(path: str, display_name: str):
    session["current_data_file"] = path
    session["dataset_name"] = display_name
    session["generated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def clear_current_dataset():
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


# ---------------------------
# Schema detection
# ---------------------------

def is_simple_schema(data: dict) -> bool:
    return isinstance(data, dict) and "users" in data and "roles" in data


def is_aws_auth_details(data: dict) -> bool:
    return isinstance(data, dict) and ("UserDetailList" in data or "RoleDetailList" in data or "GroupDetailList" in data)


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
# Policy parsing (robust, no crashes)
# ---------------------------

def extract_actions_from_statement(stmt: dict) -> set:
    """Extract allowed Action(s) from a policy statement."""
    actions = set()
    if not isinstance(stmt, dict):
        return actions
    if stmt.get("Effect", "").lower() != "allow":
        return actions
    if "Action" in stmt:
        for a in safe_list(stmt.get("Action")):
            actions.add(str(a).strip())
    return actions


def extract_actions_from_policy_doc(doc: dict) -> set:
    """Extract actions from nested policy document structure."""
    actions = set()
    if not isinstance(doc, dict):
        return actions
    for stmt in safe_list(doc.get("Statement", [])):
        actions |= extract_actions_from_statement(stmt)
    return actions


def aws_get_default_policy_doc(policy_obj: dict):
    """Return default policy version document from AWS 'Policies' structure if present."""
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
        return {"*"}  # heuristic for demo impact
    return set()


def aws_extract_principal_arns(assume_doc: dict) -> set:
    """Parse trust policy principals (Principal.AWS), supports wildcards."""
    arns = set()
    if not isinstance(assume_doc, dict):
        return arns
    for stmt in safe_list(assume_doc.get("Statement", [])):
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect", "").lower() != "allow":
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

    # Customer-managed policies with embedded docs
    customer_policy_actions = {}
    for p in safe_list(policies):
        arn = p.get("Arn")
        doc = aws_get_default_policy_doc(p)
        acts = extract_actions_from_policy_doc(doc) if doc else set()
        if arn:
            customer_policy_actions[arn] = acts

    # Groups
    group_actions = {}
    for g in safe_list(data.get("GroupDetailList", [])):
        gname = g.get("GroupName", "unknown_group")
        acts = set()
        for inline in safe_list(g.get("GroupPolicyList", [])):
            acts |= extract_actions_from_policy_doc(inline.get("PolicyDocument", {}))
        for mp in safe_list(g.get("AttachedManagedPolicies", [])):
            arn = mp.get("PolicyArn")
            acts |= customer_policy_actions.get(arn, set())
            acts |= aws_known_managed_policy_actions(arn)
        group_actions[gname] = acts

    # Users
    users = []
    for u in safe_list(data.get("UserDetailList", [])):
        uname = u.get("UserName", "unknown_user")
        uarn = u.get("Arn", f"user:{uname}")
        acts = set()
        for inline in safe_list(u.get("UserPolicyList", [])):
            acts |= extract_actions_from_policy_doc(inline.get("PolicyDocument", {}))
        for mp in safe_list(u.get("AttachedManagedPolicies", [])):
            arn = mp.get("PolicyArn")
            acts |= customer_policy_actions.get(arn, set())
            acts |= aws_known_managed_policy_actions(arn)
        for gname in safe_list(u.get("GroupList", [])):
            acts |= group_actions.get(gname, set())
        users.append({"name": uname, "arn": uarn, "actions": acts})

    # Roles
    roles = []
    for r in safe_list(data.get("RoleDetailList", [])):
        rname = r.get("RoleName", "unknown_role")
        rarn = r.get("Arn", f"role:{rname}")
        acts = set()
        for inline in safe_list(r.get("RolePolicyList", [])):
            acts |= extract_actions_from_policy_doc(inline.get("PolicyDocument", {}))
        for mp in safe_list(r.get("AttachedManagedPolicies", [])):
            arn = mp.get("PolicyArn")
            acts |= customer_policy_actions.get(arn, set())
            acts |= aws_known_managed_policy_actions(arn)
        trust = aws_extract_principal_arns(r.get("AssumeRolePolicyDocument", {}))
        roles.append({"name": rname, "arn": rarn, "actions": acts, "trust": trust})

    # admin-like roles
    def is_admin_like(actions: set) -> bool:
        low = {a.lower() for a in actions}
        return bool(low.intersection({x.lower() for x in ADMIN_ACTIONS})) or ("*" in actions)

    admin_roles = {r["arn"] for r in roles if is_admin_like(r["actions"])}

    # assume edges
    principals = {u["arn"]: u for u in users}
    principals.update({r["arn"]: r for r in roles})

    def can_assume(actions: set) -> bool:
        low = {a.lower() for a in actions}
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


# ---------------------------
# Simple schema ingestion -> normalized model
# ---------------------------

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
# Analysis
# ---------------------------

def severity_from_steps(steps: int) -> str:
    if steps <= 1:
        return "Critical"
    if steps == 2:
        return "High"
    if steps == 3:
        return "Medium"
    return "Low"


def mitre_tags(mitre_map: dict, permissions: set) -> list:
    tags = []
    for p in sorted(permissions):
        if p in mitre_map:
            t = mitre_map[p]
            tags.append({
                "permission": p,
                "technique": t.get("technique", ""),
                "id": t.get("id", ""),
                "tactic": t.get("tactic", ""),
                "note": t.get("note", ""),
            })
    return tags


def build_graph_and_findings(model: dict, mitre_map: dict):
    findings, overprivileged, conflicts = [], [], []

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
                            "Review and remove the inheritance edge that grants admin",
                            "Split privileged permissions into a dedicated admin-only role",
                            "Require approvals for role changes and audit role drift",
                        ],
                        "strategy": [
                            "Adopt Just-In-Time elevation for admin actions.",
                            "Continuously monitor role changes and alert on privilege grants."
                        ],
                        "mitre": mitre_tags(mitre_map, perms),
                    })
                    break

        telemetry = {
            "users": len(raw.get("users", [])),
            "roles": len(raw.get("roles", {})),
            "escalations": len(findings),
            "overprivileged": len(overprivileged),
            "conflicts": len(conflicts),
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

        return findings, overprivileged, conflicts, telemetry, graph_payload

    # AWS model
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

    # Escalation: user -> ... -> admin role
    for u in model["users"]:
        uarn = u["arn"]
        for target in admin_roles:
            if uarn in G.nodes and target in G.nodes and nx.has_path(G, uarn, target):
                path = nx.shortest_path(G, uarn, target)
                steps = len(path) - 1
                eff = set(u.get("actions", set())) | set(role_actions.get(target, set()))
                trust = role_trust.get(target, set())
                trust_is_wild = "*" in trust

                root_cause = "User can call sts:AssumeRole and the target role trust policy allows that principal."
                if trust_is_wild:
                    root_cause = "Target role trust policy is wildcard, allowing broad assume-role access."

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
                        "Require MFA and conditions for role assumption (aws:MultiFactorAuthPresent, source IP, session tags).",
                        "Use Permission Boundaries and/or SCPs to cap maximum privileges.",
                        "Alert on sts:AssumeRole and IAM policy changes in CloudTrail."
                    ],
                    "mitre": mitre_tags(mitre_map, {p for p in eff if isinstance(p, str)}),
                })
                break

    # Overprivileged users
    for u in model["users"]:
        acts = {a.lower() for a in u.get("actions", set())}
        flags = []
        if "*" in u.get("actions", set()):
            flags.append("Wildcard permissions detected ('*').")
        if any(a in acts for a in DANGEROUS_ACTIONS):
            flags.append("Dangerous IAM/STS actions detected (assume-role / pass-role / policy attachment).")
        if flags:
            sample = ", ".join(sorted(list(u.get("actions", set())))[:10]) or "(none)"
            overprivileged.append({
                "principal": f"user:{u['name']}",
                "permission_sample": sample,
                "flags": flags
            })

    # Conflicts (permission-based)
    for u in model["users"]:
        acts = {a.lower() for a in u.get("actions", set())}
        found = []
        for p, q in CONFLICT_PERMISSION_PAIRS:
            if p in acts and q in acts:
                found.append(f"Conflicting permissions: {p} + {q}")
        if found:
            conflicts.append({"principal": f"user:{u['name']}", "conflicts": found})

    telemetry = {
        "users": len(model.get("users", [])),
        "roles": len(model.get("roles", [])),
        "escalations": len(findings),
        "overprivileged": len(overprivileged),
        "conflicts": len(conflicts),
    }

    graph_payload = {"nodes": [], "edges": []}
    for arn, label in principals.items():
        group = "user" if arn in user_arns else "role"
        graph_payload["nodes"].append({"id": arn, "label": label, "group": group, "title": f"{label}\nARN: {arn}"})
    for e in model.get("assume_edges", []):
        graph_payload["edges"].append({"from": e["from"], "to": e["to"], "label": "can_assume", "arrows": "to"})

    return findings, overprivileged, conflicts, telemetry, graph_payload


# ---------------------------
# Routes
# ---------------------------

@app.route("/", methods=["GET"])
def home():
    st = state()
    findings, overprivileged, conflicts = [], [], []
    telemetry = {"users": 0, "roles": 0, "escalations": 0, "overprivileged": 0, "conflicts": 0}

    if st["has_data"]:
        try:
            model = ingest_dataset(current_dataset_path())
            mitre_map = load_mitre_map()
            findings, overprivileged, conflicts, telemetry, _ = build_graph_and_findings(model, mitre_map)
        except Exception as e:
            flash(f"Analysis error: {e}")
            clear_current_dataset()
            st = state()

    return render_template("index.html", title="Aegis-IAM Dashboard",
                           state=st, findings=findings,
                           overprivileged=overprivileged, conflicts=conflicts,
                           telemetry=telemetry)


@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        flash("No file provided.")
        return redirect(url_for("home"))

    f = request.files["file"]
    if not f.filename:
        flash("No selected file.")
        return redirect(url_for("home"))

    filename = secure_filename(f.filename)
    if not filename.lower().endswith(".json"):
        flash("Upload must be a .json file.")
        return redirect(url_for("home"))

    unique = f"{uuid.uuid4().hex[:10]}_{filename}"
    save_path = os.path.join(UPLOAD_DIR, unique)
    f.save(save_path)

    try:
        _ = ingest_dataset(save_path)  # validate/parse
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
    if not os.path.isfile(DEMO_FILE):
        flash("Demo dataset missing.")
        return redirect(url_for("home"))
    set_current_dataset(DEMO_FILE, "demo_aws_auth_details.json")
    flash("Simulation initialized with demo dataset.")
    return redirect(url_for("home"))


@app.route("/reset", methods=["POST"])
def reset():
    clear_current_dataset()
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
            _, _, _, _, payload = build_graph_and_findings(model, mitre_map)
        except Exception as e:
            flash(f"Graph build error: {e}")

    return render_template("graph.html", title="Graph View", state=st, graph_payload=json.dumps(payload))


@app.route("/playbook", methods=["GET"])
def playbook():
    st = state()
    findings = []

    if st["has_data"]:
        try:
            model = ingest_dataset(current_dataset_path())
            mitre_map = load_mitre_map()
            findings, _, _, _, _ = build_graph_and_findings(model, mitre_map)
        except Exception as e:
            flash(f"Playbook error: {e}")

    return render_template("playbook.html", title="Dynamic Playbook", state=st, findings=findings)


@app.route("/intel", methods=["GET"])
def intel_lab():
    return render_template("intel_lab.html", title="Intel Retrieval Lab")


if __name__ == "__main__":
    app.run(debug=True)
