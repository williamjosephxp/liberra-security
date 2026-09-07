"""
GCP Safety Layer — Generic Google Cloud REST Executor Guardrails

The GCP sibling of guardrails/aws_safety.py and guardrails/azure_safety.py. Same
four layers, same return shapes, same message tone — GCP dialect. Nothing writes to
GCP without passing through full_safety_check_gcp() first, exactly as aws_execute
calls full_safety_check() and azure_execute calls full_safety_check_azure().

GCP's control plane is uniform JSON/REST over *.googleapis.com hosts, so — like ARM
for Azure — the HTTP method + URL shape ARE most of the classifier. The one wrinkle
GCP adds over Azure: some reads are GETs that expose secrets (Secret Manager
versions:access) and some destructive ops are custom colon-verbs (:destroy, :purge)
rather than the HTTP DELETE method. Both are handled here so a GET-only read tool and
a POST/PUT/PATCH write tool are each fully covered.

Layers:
  A. Global destruction hard-block — HTTP DELETE + custom destroy/purge/delete verbs.
  B. NEVER_ALLOWED nuclear API hosts (billing, identity/Workspace, org policy, VPC-SC,
     token minting) + the org/folder tier of Resource Manager. Absolute — enforced even
     under the internal-tier bypass. Project-scoped Resource Manager reads stay allowed.
  C. BLOCKED_OPERATIONS — targeted non-delete backdoor / credential / audit-blinding
     (all IAM writes, unsafe setIamPolicy, logging exclusions/sinks, SCC mute configs,
     Secret Manager value access).
  D. DANGEROUS_PATTERNS — conditional, body-inspecting (open firewalls, public storage
     ACLs, bulk instance launches, disabling Cloud SQL backups).

Return shapes (OperationSafety, PatternResult, SafetyLevel) are imported verbatim from
aws_safety so loop.py:_classify_gate and the executor read GCP results identically —
one gate, three dialects.
"""

import logging
from typing import Optional, Tuple
from urllib.parse import urlparse, unquote

# Reuse the exact same result shapes + level enum as AWS/Azure so the loop's
# provider-agnostic gate + the executor read them identically.
from guardrails.aws_safety import (
    SafetyLevel,
    OperationSafety,
    PatternResult,
)

logger = logging.getLogger(__name__)

# Ports that should never be open to the world — identical to the AWS/Azure set.
_SENSITIVE_PORTS = {22, 3389, 3306, 5432, 27017, 6379, 1433, 9200, 9300, 5439}

# "Source = the whole internet" CIDRs on a GCP firewall (IPv4 + IPv6).
_WORLD_SOURCE_TOKENS = {"0.0.0.0/0", "::/0"}

# The two public IAM principals — the GCP analog of an S3 "Principal: *" / an Azure
# publicAccess. A binding naming either exposes the resource to the whole internet.
_PUBLIC_PRINCIPALS = {"allusers", "allauthenticatedusers"}


# =============================================================================
# LAYER B — NEVER_ALLOWED nuclear API hosts
# =============================================================================
# Blocked by API host for ALL methods (reads included) — these are account/org/identity
# planes, not resource management. Mirrors AWS NEVER_ALLOWED (organizations/sts/account/
# sso/identitystore) and Azure's nuclear namespaces. Absolute even for the internal tier.
_NUCLEAR_HOSTS = frozenset({
    "cloudbilling.googleapis.com",          # billing accounts / project-billing = financial takeover (AWS: account)
    "cloudidentity.googleapis.com",         # groups/memberships = org identity (AWS: identitystore)
    "admin.googleapis.com",                 # Workspace Admin SDK = directory takeover (AWS: sso-admin)
    "orgpolicy.googleapis.com",             # org policy constraints = guardrail teardown (AWS: organizations)
    "accesscontextmanager.googleapis.com",  # VPC Service Controls perimeters = security-boundary control (AWS: organizations)
    "iamcredentials.googleapis.com",        # mints tokens / signs as any SA — that's OUR auth plane (AWS: sts)
})

# Resource Manager is allowed at the PROJECT tier (get/list a project) but is nuclear at
# the organization/folder tier — moving or re-parenting projects restructures the account.
_CRM_HOST = "cloudresourcemanager.googleapis.com"

# Curated non-admin predefined roles that setIamPolicy may grant (Layer C½). Kept
# deliberately small — read-only + narrow client roles only. The GCP analog of AWS's
# "AWS-managed policies minus the nuclear ones". Anything not on this list is denied.
# Cited: these are all Google predefined roles (cloud.google.com/iam/docs/understanding-roles).
_ALLOWED_IAM_ROLES = frozenset({
    "roles/viewer",                 # project-wide read
    "roles/logging.viewer",         # read logs
    "roles/monitoring.viewer",      # read metrics
    "roles/storage.objectViewer",   # read GCS objects
    "roles/pubsub.subscriber",      # consume a subscription
    "roles/cloudsql.client",        # connect to Cloud SQL (no admin)
})


# =============================================================================
# URL / body helpers
# =============================================================================

def _split(url: str) -> Tuple[str, str]:
    """(host, path) from a GCP REST URL. host lowercased; path percent-decoded so a
    caller can't dodge the colon-verb / segment checks below by encoding the literal
    ':' as '%3A' (or any other reserved char) — decode once here so every check downstream
    (destroy/purge verbs, org/folder tier, setIamPolicy detection, secret :access) sees
    the same path a real HTTP router would dispatch on."""
    u = urlparse(url or "")
    return (u.hostname or "").lower(), unquote(u.path or "")


def _trailing(path: str) -> str:
    """Lowercased final path segment (colon verb included). '' for an empty path."""
    seg = (path or "").rstrip("/").rsplit("/", 1)[-1]
    return seg.lower()


def _colon_verb(path: str) -> str:
    """The custom method after ':' in the last segment (e.g. '...cryptoKeyVersions/1:destroy'
    → 'destroy'). '' when the last segment carries no colon verb."""
    last = _trailing(path)
    return last.split(":", 1)[1] if ":" in last else ""


# Colon verbs that READ, even though they arrive as POST.
#
# GCP does not use the HTTP verb to say what an operation does — it uses the custom
# method after ':'. `:destroy` is already handled below for the same reason. This is the
# other half of that fact, and it was missing: classification treated GET as the only
# read, so every POST-shaped read fell through to the write branch and asked the user to
# approve a lookup. `cloudasset:searchAllResources` — the query that returns a whole
# project in one call, GCP's answer to Azure Resource Graph — needed a confirmation card.
#
# Deliberately a short, conservative list of verbs that only ever return data. Anything
# not named here stays a write, which is the safe direction: an unlisted read costs one
# approval click, an unlisted write costs the user something real. `:exportAssets` is
# excluded on purpose — it READS assets but WRITES them to a bucket.
_READ_COLON_VERBS = frozenset({
    "get", "list", "search",
    "getiampolicy", "testiampermissions",
    "searchallresources", "searchalliampolicies",
    "batchget", "batchgetassetshistory",
    "queryassets", "analyzeiampolicy",
})


def _lk(obj):
    """Deep copy with dict keys lowercased (values untouched) — lets body checkers read
    GCP's camelCase fields case-insensitively, since Claude's casing can vary."""
    if isinstance(obj, dict):
        return {str(k).lower(): _lk(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_lk(v) for v in obj]
    return obj


def _is_set_iam_policy(host: str, path_l: str, method: str) -> bool:
    """True when this call sets an IAM policy — the GCP privilege-grant surface.
    Handles all three shapes: a ':setIamPolicy' colon verb (Resource Manager, IAM),
    a '/setIamPolicy' path segment (Compute), and Storage's '/b/<bucket>/iam' PUT."""
    if _colon_verb(path_l) == "setiampolicy":
        return True
    seg = _trailing(path_l).split(":", 1)[0]
    if seg == "setiampolicy":
        return True
    if host == "storage.googleapis.com" and seg == "iam" and method in ("PUT", "PATCH", "POST"):
        return True
    return False


def _extract_bindings(body) -> list:
    """The IAM bindings list from a setIamPolicy body. Compute/Resource Manager wrap it
    as {"policy": {"bindings": [...]}}; Storage sends {"bindings": [...]} directly."""
    if not isinstance(body, dict):
        return []
    pol = body.get("policy")
    if isinstance(pol, dict) and isinstance(pol.get("bindings"), list):
        return pol["bindings"]
    if isinstance(body.get("bindings"), list):
        return body["bindings"]
    return []


# =============================================================================
# LAYER B entry point — is_nuclear_gcp (absolute even under the internal bypass)
# =============================================================================

def is_nuclear_gcp(url: str) -> bool:
    """True when Layer B applies — a nuclear API host, or the org/folder tier of
    Resource Manager. Used by the executor to keep Layer B hard even under the
    internal-tier bypass, the GCP analog of AWS NEVER_ALLOWED / Azure is_nuclear_azure."""
    host, path = _split(url)
    if host in _NUCLEAR_HOSTS:
        return True
    if host == _CRM_HOST:
        pl = path.lower()
        if "/organizations/" in pl or pl.rstrip("/").endswith("/organizations"):
            return True
        if "/folders/" in pl or pl.rstrip("/").endswith("/folders"):
            return True
    return False


_NUCLEAR_MESSAGES = {
    "cloudbilling.googleapis.com": "Billing changes are blocked — moving a project's billing account or "
                                   "editing billing is a financial-takeover risk. Manage billing in the Cloud Console.",
    "cloudidentity.googleapis.com": "Cloud Identity (groups and memberships) is blocked — it's org-level identity, "
                                    "not project resources. Manage it in the Admin console.",
    "admin.googleapis.com": "The Workspace Admin API is blocked — it manages your whole directory, not this project. "
                            "Use the Admin console.",
    "orgpolicy.googleapis.com": "Organization Policy changes are blocked — they set the guardrails above your "
                                "projects. Manage them in the Cloud Console.",
    "accesscontextmanager.googleapis.com": "Access Context Manager (VPC Service Controls) is blocked — it controls "
                                           "your security perimeter. Manage it in the Cloud Console.",
    "iamcredentials.googleapis.com": "Minting service-account tokens is blocked — that's Liberra's own auth path and "
                                     "a credential-escalation risk. This is never available through the tool.",
}


# =============================================================================
# LAYER A + B + C — classify_gcp_operation
# =============================================================================

def classify_gcp_operation(method: str, url: str, body=None) -> OperationSafety:
    """Classify a GCP REST call by safety level.

    Order matters: host invariant → Layer B (nuclear, any method) → GET reads
    (with the Secret Manager value-access carve-out) → Layer A (destruction) →
    Layer C (backdoor/credential/audit) → gated WRITE.
    """
    m = (method or "").strip().upper()
    host, path = _split(url)
    p = path.lower()

    # Host invariant — only Google Cloud APIs are reachable (mirrors Azure's ARM-host lock).
    if not host or not host.endswith(".googleapis.com"):
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message="Only Google Cloud APIs (https://<service>.googleapis.com/...) are reachable. "
                    "That URL isn't a googleapis.com host.",
        )

    # ── Layer B: nuclear hosts / org tier — blocked for ALL methods, reads included ──
    if is_nuclear_gcp(url):
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message=_NUCLEAR_MESSAGES.get(
                host,
                "This is an organization/folder-level Resource Manager operation — it can move or "
                "re-parent projects and restructure the account. Project-scoped reads are fine; "
                "org/folder changes are not available through Liberra.",
            ),
        )

    # ── Reads: a GET, or a POST whose colon verb only ever returns data ──
    if m == "GET" or _colon_verb(p) in _READ_COLON_VERBS:
        # Secret Manager exposes secret material via GET .../versions/<v>:access — the GCP
        # analog of secretsmanager:get_secret_value, which a GET-only tool would otherwise reach.
        if host == "secretmanager.googleapis.com" and _colon_verb(p) == "access":
            return OperationSafety(
                level=SafetyLevel.BLOCKED,
                message="Reading a secret's value is blocked — it exposes credentials. Liberra can list "
                        "and describe secrets, but not fetch their contents.",
            )
        how = "GET" if m == "GET" else f"POST :{_colon_verb(p)}"
        return OperationSafety(level=SafetyLevel.READ, message=f"Read operation (GCP {how}).")

    # ── Layer A: global destruction hard-block ──
    if m == "DELETE":
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message="Delete operations are blocked — Liberra never issues a DELETE. Use the Cloud "
                    "Console for resource removal.",
        )
    verb = _colon_verb(p)
    if verb.startswith("delete") or verb in ("destroy", "purge"):
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message=f"'{verb}' is blocked — it permanently destroys the resource (delete/destroy/purge "
                    "class). This can't be undone. Use the Cloud Console if you truly must.",
        )

    # ── Layer C: targeted backdoor / credential / audit-blinding ──
    # All IAM writes blocked — SA-key creation is a long-lived-credential backdoor, SA/role
    # creation is privilege escalation (AWS: iam:create_access_key/create_user; the whole IAM
    # write block minus attach/detach). setIamPolicy ON iam.googleapis.com (impersonation grant)
    # is caught here too, so this must precede the param-gated setIamPolicy carve-out below.
    if host == "iam.googleapis.com":
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message="Identity & Access Management writes are blocked — creating service accounts, "
                    "service-account keys, or roles hands out long-lived credentials and escalates "
                    "privilege. Manage these in the Cloud Console (IAM & Admin).",
        )

    # setIamPolicy on any OTHER service — param-gated to safe read/narrow roles + real principals.
    # The GCP analog of "IAM attach blocked except AWS-managed non-nuclear policies".
    if _is_set_iam_policy(host, p, m):
        return _check_set_iam_policy(body)

    # Audit / security blinding — the attacker's first move (AWS: cloudtrail:stop_logging,
    # config:stop_configuration_recorder, guardduty:disassociate_*).
    if host == "logging.googleapis.com":
        if "/exclusions" in p:
            return OperationSafety(
                level=SafetyLevel.BLOCKED,
                message="Creating or changing a logging exclusion is blocked — it silently drops log "
                        "entries (audit-blinding). Manage exclusions in the Cloud Console.",
            )
        if "/sinks" in p and m in ("PUT", "PATCH"):
            return OperationSafety(
                level=SafetyLevel.BLOCKED,
                message="Modifying a log sink is blocked — it can redirect or sever the audit trail. "
                        "Manage sinks in the Cloud Console.",
            )
    if host == "securitycenter.googleapis.com" and "/muteconfigs" in p:
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message="Creating a Security Command Center mute config is blocked — it suppresses security "
                    "findings (audit-blinding). Manage mute configs in the Cloud Console.",
        )

    # ── Everything else that mutates: gated write ──
    if m in ("PUT", "PATCH", "POST"):
        return OperationSafety(level=SafetyLevel.WRITE, message=f"Write operation (GCP {m}).")

    # Unknown verb — fail safe to WRITE (requires confirmation).
    logger.warning(f"Unknown GCP method '{method}' for {url}, defaulting to WRITE")
    return OperationSafety(
        level=SafetyLevel.WRITE,
        message=f"Unknown method '{method}'. Treating as write (requires confirmation).",
    )


def _check_set_iam_policy(body) -> OperationSafety:
    """The one setIamPolicy carve-out: allow ONLY bindings that grant a small allow-list of
    non-admin roles to real (serviceAccount:/user:) principals. Any public principal
    (allUsers/allAuthenticatedUsers), any domain: grant, any off-list role, or a missing
    binding set → BLOCKED. One bad binding poisons the whole request (fail-safe).

    Mirrors AWS _check_iam_policy_attach: sanctioned surface only, everything else denied.
    """
    bindings = _extract_bindings(body)
    if not bindings:
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message="This IAM policy change has no readable bindings, so Liberra can't verify it's safe. "
                    "Include the policy bindings (role + members) and retry.",
        )

    for b in bindings:
        if not isinstance(b, dict):
            return OperationSafety(level=SafetyLevel.BLOCKED, message="Malformed IAM binding — can't verify it's safe.")
        role = str(b.get("role", "")).strip()
        if role not in _ALLOWED_IAM_ROLES:
            return OperationSafety(
                level=SafetyLevel.BLOCKED,
                message=f"Granting '{role or '(no role)'}' via Liberra is blocked — only a small set of "
                        "read-only / narrow roles can be granted through the tool (Owner, Editor, and any "
                        "admin/IAM role are never allowed). Manage broader grants in the Cloud Console.",
            )
        members = b.get("members") or []
        if not isinstance(members, list):
            members = [members]
        for mbr in members:
            ml = str(mbr).strip().lower()
            if ml in _PUBLIC_PRINCIPALS:
                return OperationSafety(
                    level=SafetyLevel.BLOCKED,
                    message="This grant exposes the resource to the public (allUsers / allAuthenticatedUsers) "
                            "and is blocked. Grant to a specific service account or user instead.",
                )
            if ml.startswith("domain:"):
                return OperationSafety(
                    level=SafetyLevel.BLOCKED,
                    message="Granting to an entire domain is blocked — it's too broad. Grant to a specific "
                            "service account or user instead.",
                )
            if not (ml.startswith("serviceaccount:") or ml.startswith("user:")):
                return OperationSafety(
                    level=SafetyLevel.BLOCKED,
                    message=f"'{mbr}' isn't an allowed IAM principal — only 'serviceAccount:' and 'user:' "
                            "members can be granted access through Liberra.",
                )

    return OperationSafety(
        level=SafetyLevel.WRITE,
        message="IAM policy binding (narrow role to a specific principal).",
        confirmation_message="Grant an IAM role binding — this changes who can access the resource. "
                             "Verify the role and principal.",
    )


# =============================================================================
# LAYER D — DANGEROUS_PATTERNS (conditional, body-inspecting)
# =============================================================================

def check_gcp_patterns(method: str, url: str, body=None) -> PatternResult:
    """Conditional body checks — open firewalls, public storage ACLs, bulk launches,
    disabling Cloud SQL backups. Only meaningful for writes."""
    m = (method or "").strip().upper()
    if m not in ("PUT", "PATCH", "POST"):
        return PatternResult()

    host, path = _split(url)
    p = path.lower()
    lb = _lk(body) if isinstance(body, dict) else {}

    if host == "compute.googleapis.com":
        if "/firewalls" in p:
            return _check_firewall(lb)                       # AWS: authorize_security_group_ingress
        if p.rstrip("/").endswith("/bulkinsert"):
            return _check_bulk_insert(lb)                    # AWS: run_instances MaxCount

    if host == "storage.googleapis.com":
        seg = _trailing(p).split(":", 1)[0]
        if seg in ("defaultobjectacl", "acl") or "/acl/" in p:
            return _check_storage_acl(lb)                    # AWS: put_bucket_acl (public)

    if host == "sqladmin.googleapis.com":
        if m == "PATCH" and "/instances/" in p:
            return _check_sql_backup(lb)                     # posture: don't silently kill backups

    return PatternResult()


def _check_firewall(body: dict) -> PatternResult:
    """Block firewalls that expose sensitive ports (or all ports) to the whole internet.
    Mirrors _check_sg_ingress: world CIDR + sensitive/all ports → block; a plain web port
    (80/443, etc.) → warn, matching AWS which never lists 80/443 as sensitive."""
    ranges = body.get("sourceranges") or []
    if not any(str(r).strip().lower() in _WORLD_SOURCE_TOKENS for r in ranges):
        return PatternResult()

    exposed = set()
    all_ports_world = False
    non_sensitive_world = False

    allowed = body.get("allowed") or []
    if not isinstance(allowed, list):
        allowed = []
    for rule in allowed:
        if not isinstance(rule, dict):
            continue
        proto = str(rule.get("ipprotocol", "")).strip().lower()
        ports = rule.get("ports")
        # IPProtocol "all", or a protocol with no ports listed = every port for it.
        if proto == "all" or ports is None:
            all_ports_world = True
            continue
        if not isinstance(ports, list):
            ports = [ports]
        for pr in ports:
            pr = str(pr).strip()
            if pr == "" or pr == "*":
                all_ports_world = True
                continue
            try:
                if "-" in pr:
                    lo, hi = pr.split("-", 1)
                    rng = range(int(lo), int(hi) + 1)
                else:
                    rng = [int(pr)]
            except (ValueError, TypeError):
                non_sensitive_world = True
                continue
            hit = _SENSITIVE_PORTS.intersection(rng)
            if hit:
                exposed.update(hit)
            else:
                non_sensitive_world = True

    if all_ports_world:
        return PatternResult(
            blocked=True,
            message="Opening all ports to the internet (0.0.0.0/0) is blocked. Restrict sourceRanges to "
                    "your VPC or a known IP range.",
        )
    if exposed:
        return PatternResult(
            blocked=True,
            message=f"Opening ports {sorted(exposed)} to the internet (0.0.0.0/0) is blocked — these are "
                    "sensitive service ports (SSH, RDP, databases). Restrict sourceRanges to a known IP range.",
        )
    if non_sensitive_world:
        return PatternResult(
            warning="This firewall allows inbound traffic from the whole internet (0.0.0.0/0). "
                    "Make sure that's intended.",
            exposure="open this port to the internet",
        )
    return PatternResult()


def _check_bulk_insert(body: dict) -> PatternResult:
    """Cap bulk instance launches — the GCP analog of EC2 run_instances MaxCount."""
    count = body.get("count")
    try:
        count = int(count)
    except (ValueError, TypeError):
        return PatternResult()
    if count > 20:
        return PatternResult(
            blocked=True,
            message=f"Launching {count} instances at once is blocked. Maximum is 20 via the generic executor.",
        )
    if count > 10:
        return PatternResult(warning=f"Launching {count} instances. This will incur significant charges.")
    return PatternResult()


def _check_storage_acl(body: dict) -> PatternResult:
    """Block ACL-style bodies that make a bucket/object public (entity allUsers /
    allAuthenticatedUsers). The setIamPolicy path to public is caught in Layer C½;
    this is the older objectAccessControls/acl shape. Mirrors _check_s3_bucket_acl."""
    entity = str(body.get("entity", "")).strip().lower()
    if entity in _PUBLIC_PRINCIPALS:
        return PatternResult(
            blocked=True,
            message="Making this bucket/object publicly readable (entity allUsers / allAuthenticatedUsers) "
                    "is blocked — anonymous access exposes its data. Use signed URLs or grant a specific principal.",
        )
    return PatternResult()


def _check_sql_backup(body: dict) -> PatternResult:
    """Block disabling automated backups on a Cloud SQL instance (removes the recovery
    path). Mirrors the spirit of AWS's RDS 'delete without final snapshot' block."""
    settings = body.get("settings")
    if not isinstance(settings, dict):
        return PatternResult()
    bc = settings.get("backupconfiguration")
    if isinstance(bc, dict):
        enabled = bc.get("enabled")
        if enabled is False or str(enabled).strip().lower() == "false":
            return PatternResult(
                blocked=True,
                message="Disabling automated backups on this Cloud SQL instance is blocked — it removes the "
                        "recovery path if data is lost. Keep backups on, or change this in the Cloud Console.",
            )
    return PatternResult()


# =============================================================================
# Always-gate classification (the "open ports" class — re-prompts every time)
# =============================================================================

def gcp_op_always_gates(method: str, url: str, body=None) -> bool:
    """True for the security-posture / access-grant class that must re-prompt every time,
    even under one-yes-per-message approval. GCP analog of AWS _ALWAYS_GATE_OPS /
    Azure azure_op_always_gates: any setIamPolicy, firewall write, public-exposure ACL,
    or Cloud SQL settings patch."""
    m = (method or "").strip().upper()
    if m not in ("PUT", "PATCH", "POST"):
        return False
    host, path = _split(url)
    p = path.lower()

    if _is_set_iam_policy(host, p, m):                       # IAM grant
        return True
    if host == "compute.googleapis.com" and "/firewalls" in p:   # open-ports class
        return True
    if host == "storage.googleapis.com":                    # public-exposure ACL
        seg = _trailing(p).split(":", 1)[0]
        if seg in ("defaultobjectacl", "acl") or "/acl/" in p:
            return True
    if host == "sqladmin.googleapis.com" and m == "PATCH" and "/instances/" in p:  # backup posture
        return True
    return False


# =============================================================================
# Full Safety Check (combines all layers) — the single entry point
# =============================================================================

def full_safety_check_gcp(
    method: str,
    url: str,
    body=None,
    internal_bypass: bool = False,
) -> Tuple[OperationSafety, PatternResult]:
    """Run all GCP safety layers for one REST call.

    The GCP sibling of full_safety_check() / full_safety_check_azure(). Returns
    (OperationSafety, PatternResult) with the exact same shapes AWS/Azure return, so
    loop.py:_classify_gate and the executor read them identically.

    internal_bypass=True resolves the internal-tier bypass in place (the loop injects
    _internal_bypass for internal users): Layer A/C blocks and Layer D pattern blocks are
    downgraded to a gated write, so an internal user can test them — but Layer B (nuclear)
    stays BLOCKED, exactly like AWS NEVER_ALLOWED / Azure nuclear namespaces stay hard.
    The gate itself calls this WITHOUT the bypass (default False) and so sees the true
    classification.
    """
    safety = classify_gcp_operation(method, url, body)
    pattern = check_gcp_patterns(method, url, body)

    if internal_bypass and not is_nuclear_gcp(url):
        if safety.level == SafetyLevel.BLOCKED:
            safety = OperationSafety(
                level=SafetyLevel.WRITE,
                message="[internal bypass] " + safety.message,
            )
        if pattern.blocked:
            pattern = PatternResult(blocked=False, warning="[internal bypass] " + (pattern.message or ""))

    return safety, pattern
