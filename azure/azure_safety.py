"""
Azure Safety Layer — Generic ARM Executor Guardrails

The Azure sibling of guardrails/aws_safety.py. Same four layers, same return
shapes, same message tone — Azure dialect. Nothing writes to Azure without
passing through full_safety_check_azure() first, exactly as aws_execute calls
full_safety_check().

The one structural difference: Azure's management plane is uniform ARM REST, so
the HTTP verb IS the safety classifier. DELETE is a single, total, future-proof
delete block — no per-service keyword tables. See AZURE_SAFETY_SPEC.md.

Layers:
  A. Global destruction hard-block — HTTP DELETE + purge-style POST actions.
  B. NEVER_ALLOWED nuclear ARM namespaces (RBAC, org tree, subscription, billing,
     Lighthouse, B2C). Absolute — enforced even for the internal-tier bypass.
     ONE exception: roleAssignments PUT to a built-in (non-nuclear) role, always-gated.
  C. BLOCKED_OPERATIONS — targeted non-delete backdoor / credential / audit-blinding.
  D. DANGEROUS_PATTERNS — conditional, parameter-inspecting (open ports, public
     storage, SQL firewall, etc.).

Return shapes (OperationSafety, PatternResult, SafetyLevel) are imported verbatim
from aws_safety so the loop's provider-agnostic gate reads them identically.
"""

import json
import logging
from typing import Optional, Tuple

# Reuse the exact same result shapes + level enum as AWS so loop.py:_classify_gate
# and the executor read them identically — one gate, two dialects.
from guardrails.aws_safety import (
    SafetyLevel,
    OperationSafety,
    PatternResult,
)

logger = logging.getLogger(__name__)

# The host invariant: azure_read / azure_execute only ever speak to the ARM
# management plane. Graph and data-plane are out of scope by construction.
_ARM_HOST = "management.azure.com"

# Ports that should never be open to the world — identical to the AWS set.
_SENSITIVE_PORTS = {22, 3389, 3306, 5432, 27017, 6379, 1433, 9200, 9300, 5439}

# The three Azure "source = the whole internet" tokens. AWS has only the CIDR;
# Azure adds "*" and the named "Internet" service tag.
_WORLD_SOURCE_TOKENS = {"*", "0.0.0.0/0", "internet"}


# =============================================================================
# LAYER B — NEVER_ALLOWED nuclear ARM namespaces
# =============================================================================
# Blocked by provider namespace anywhere in the resource path (these are often
# extension resources that hang off any scope). Mirrors AWS NEVER_ALLOWED.
# Lowercase — ARM paths are case-insensitive and normalized before matching.
_NUCLEAR_NAMESPACES = frozenset({
    "microsoft.authorization",      # RBAC grant/escalation (roleAssignments/Definitions/denyAssignments)
    "microsoft.management",         # management groups — the org tree above subscriptions
    "microsoft.subscription",       # cancel/rename/move the subscription = close the account
    "microsoft.billing",            # billing accounts / billingRoleAssignments = financial takeover
    "microsoft.consumption",        # consumption/budget writes on the billing side
    "microsoft.managedservices",    # Lighthouse — grants an EXTERNAL tenant standing access
    "microsoft.azureactivedirectory",  # B2C directories — identity federation tampering
})

# Well-known built-in role GUIDs that grant privilege escalation. Blocked even
# though they are built-in — the direct analog of AWS's _BLOCKED_IAM_MANAGED_POLICIES
# (AdministratorAccess/PowerUserAccess/IAMFullAccess). Everything else built-in is
# allowed (param-gated, always re-prompt).
_NUCLEAR_ROLE_GUIDS = frozenset({
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
    "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",  # User Access Administrator
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168",  # Role Based Access Control Administrator
})

# A built-in role definition is referenced at the tenant root. A custom role's id
# is scoped (starts with /subscriptions/... or a management-group scope). We allow
# only the tenant-scoped built-in form — the Azure analog of "arn:aws:iam::aws:policy/".
_BUILTIN_ROLE_DEF_PREFIX = "/providers/microsoft.authorization/roledefinitions/"

# ARM endpoints that take a query in the body — POST on the wire, read in effect.
# Deliberately an exact-suffix list and deliberately short: every entry is an API
# whose entire job is to return data. Adding to it is a safety decision, not a
# convenience one.
_READ_ONLY_QUERY_PATHS = (
    "/providers/microsoft.costmanagement/query",      # spend, grouped/filtered
    "/providers/microsoft.costmanagement/forecast",   # projected spend
    "/providers/microsoft.resourcegraph/resources",   # KQL across subscriptions
)


# =============================================================================
# Path / body helpers
# =============================================================================

def _norm_path(path: str) -> str:
    """Lowercase, drop any query string. ARM paths are case-insensitive."""
    return (path or "").split("?", 1)[0].strip().lower()


def _lower_keys(obj):
    """Deep copy with all dict keys lowercased (values untouched). Lets pattern
    checkers read camelCase body fields case-insensitively — Claude's casing may vary."""
    if isinstance(obj, dict):
        return {str(k).lower(): _lower_keys(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_lower_keys(v) for v in obj]
    return obj


def _props(body) -> dict:
    """The lowercased `properties` sub-dict of an ARM body ({} if absent)."""
    lb = _lower_keys(body) if isinstance(body, dict) else {}
    p = lb.get("properties")
    return p if isinstance(p, dict) else {}


def _resolve_role_definition_id(path_l: str, body) -> str:
    """Lowercased roleDefinitionId from the body (the only place a PUT carries it)."""
    props = _props(body)
    rid = props.get("roledefinitionid") or ""
    return str(rid).lower()


def _check_role_assignment(method: str, path_l: str, body) -> Tuple[bool, str]:
    """The one Microsoft.Authorization exception: assigning a built-in role.

    Mirrors AWS _check_iam_policy_attach — allow only the sanctioned namespace
    (built-in roles), deny custom/scoped role definitions and the nuclear escalation
    roles. Returns (allowed, deny_message).
    """
    is_role_assignment = (
        "/roleassignments/" in path_l or path_l.rstrip("/").endswith("/roleassignments")
    )
    if method != "PUT" or not is_role_assignment:
        return False, (
            "Microsoft.Authorization writes are blocked — RBAC role definitions, deny "
            "assignments, and non-PUT role changes grant or escalate access across the whole "
            "scope. Manage roles in the Azure portal (IAM blade)."
        )

    rid = _resolve_role_definition_id(path_l, body)
    if not rid:
        return False, (
            "Role assignment blocked — no roleDefinitionId was provided, so Liberra can't "
            "verify it's a built-in role. Include the built-in role's roleDefinitionId and retry."
        )

    guid = rid.rstrip("/").split("/")[-1]
    if guid in _NUCLEAR_ROLE_GUIDS:
        return False, (
            "Assigning Owner, Contributor, or User Access Administrator is blocked — that grants "
            "near-total control of the scope (privilege escalation). Assign a narrower built-in "
            "role, or make this change in the Azure portal."
        )

    if not rid.startswith(_BUILTIN_ROLE_DEF_PREFIX):
        return False, (
            "Only built-in Azure roles can be assigned via Liberra — this references a custom or "
            "scoped role definition. Use a built-in role, or manage custom-role assignments in the "
            "Azure portal."
        )

    return True, ""


def _is_nuclear_path(path_l: str) -> Optional[str]:
    """Return the nuclear namespace present in the path, or None."""
    for ns in _NUCLEAR_NAMESPACES:
        if f"/providers/{ns}/" in path_l or path_l.rstrip("/").endswith(f"/providers/{ns}"):
            return ns
    return None


def is_nuclear_azure(method: str, path: str, body=None) -> bool:
    """True when Layer B applies and the op is NOT the sanctioned built-in role
    assignment. Used by the executor to keep Layer B absolute even under the
    internal-tier bypass — the Azure analog of NEVER_ALLOWED staying hard even
    for internal users.
    """
    m = (method or "").strip().upper()
    if m == "GET":
        return False
    p = _norm_path(path)
    ns = _is_nuclear_path(p)
    if ns is None:
        return False
    if ns == "microsoft.authorization":
        allowed, _ = _check_role_assignment(m, p, body)
        if allowed:
            return False
    return True


# =============================================================================
# LAYER A + B + C — classify_azure_operation
# =============================================================================

def classify_azure_operation(method: str, path: str, body=None) -> OperationSafety:
    """Classify an ARM call by safety level.

    GET  → READ (free; azure_read handles reads, but total for correctness).
    DELETE → BLOCKED (Layer A — the kill switch).
    POST .../purge → BLOCKED (Layer A — irreversible soft-delete bypass).
    nuclear namespace → BLOCKED (Layer B), except built-in roleAssignment PUT → WRITE.
    Layer C backdoor/credential/audit op → BLOCKED.
    otherwise PUT/PATCH/POST → WRITE (gated).
    """
    m = (method or "").strip().upper()
    p = _norm_path(path)

    # Host invariant — never anything but the ARM management plane.
    if "graph.microsoft.com" in p or "://" in p:
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message="Only the Azure Resource Manager management plane is reachable. "
                    "Directory (Microsoft Graph) and data-plane calls are out of scope.",
        )

    if m == "GET":
        return OperationSafety(level=SafetyLevel.READ, message="Read operation (ARM GET).")

    # ── Layer A: global destruction hard-block ──
    if m == "DELETE":
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message="Delete operations are blocked — Liberra never issues an ARM DELETE. "
                    "Use the Azure portal for resource removal.",
        )
    if m == "POST" and p.rstrip("/").endswith("/purge"):
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message="Purge is blocked — it permanently destroys a soft-deleted resource, "
                    "bypassing recovery. This cannot be undone. Use the Azure portal if you "
                    "truly must purge.",
        )

    # ── Layer B: nuclear namespaces ──
    ns = _is_nuclear_path(p)
    if ns is not None:
        if ns == "microsoft.authorization":
            allowed, deny_msg = _check_role_assignment(m, p, body)
            if allowed:
                return OperationSafety(
                    level=SafetyLevel.WRITE,
                    message="RBAC role assignment (built-in role).",
                    confirmation_message="Assign a built-in Azure role — this grants access. Verify the assignee and role.",
                )
            return OperationSafety(level=SafetyLevel.BLOCKED, message=deny_msg)
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message=_NUCLEAR_MESSAGES.get(
                ns,
                f"'{ns}' is blocked — an account/tenant-level service that can take over or "
                f"restructure the subscription. Not available through Liberra.",
            ),
        )

    # ── Layer C: targeted backdoor / credential / audit-blinding ops ──
    blocked = _check_blocked_azure(m, p, body)
    if blocked is not None:
        return blocked

    # ── Query endpoints: POST on the wire, a READ in every way that matters ──
    #
    # Classify by what the operation DOES, not by its HTTP verb — that is exactly
    # how the AWS side works. Every boto3 `describe_*` / `list_*` is an HTTP POST
    # under the hood, and aws_safety classifies it READ from the operation name.
    # Azure has the same shape for its query APIs: Cost Management and Resource
    # Graph take a query in the request body, so they must be POSTs, but they
    # cannot create, modify or delete anything.
    #
    # Without this, asking "what am I spending on Azure?" raises an approve box —
    # or is simply unanswerable — while the identical AWS question is free.
    #
    # EXACT paths only, never a pattern. In Azure the POST verb is also how you
    # fetch storage keys and SAS tokens (see _CREDENTIAL_ACTIONS), so a rule like
    # "POST ending in /query is a read" would reopen that door. Layer C runs first
    # regardless, as a second line of defence.
    if m == "POST" and p.rstrip("/").endswith(_READ_ONLY_QUERY_PATHS):
        return OperationSafety(
            level=SafetyLevel.READ,
            message="Read operation (ARM query endpoint — returns data, mutates nothing).",
        )

    # ── Everything else that mutates: gated write ──
    if m in ("PUT", "PATCH", "POST"):
        return OperationSafety(
            level=SafetyLevel.WRITE,
            message=f"Write operation (ARM {m}).",
        )

    # Unknown verb — fail safe to WRITE (requires confirmation).
    logger.warning(f"Unknown ARM method '{method}' for {path}, defaulting to WRITE")
    return OperationSafety(
        level=SafetyLevel.WRITE,
        message=f"Unknown ARM method '{method}'. Treating as write (requires confirmation).",
    )


_NUCLEAR_MESSAGES = {
    "microsoft.management": "Management-group changes are blocked — that's the org tree above your "
                            "subscriptions. Manage it in the Azure portal.",
    "microsoft.subscription": "Subscription-level changes (cancel/rename/move) are blocked — this "
                              "is the equivalent of closing or moving the account.",
    "microsoft.billing": "Billing changes are blocked — moving a subscription between billing accounts "
                         "or minting a billing admin is a financial-takeover risk.",
    "microsoft.consumption": "Billing/consumption writes are blocked — financial-control risk.",
    "microsoft.managedservices": "Azure Lighthouse (delegated resource management) is blocked — it grants "
                                 "an external tenant standing access to your subscription.",
    "microsoft.azureactivedirectory": "Azure AD B2C directory changes are blocked — identity-federation "
                                      "tampering. Manage B2C in the Azure portal.",
}


# =============================================================================
# LAYER C — targeted blocked operations
# =============================================================================

# Actions that hand back a LIVE CREDENTIAL. Azure's convention is a POST "action"
# on the resource, and the convention is used across a dozen namespaces —
# storage, Cosmos DB, Event Hubs, Service Bus, ACR, Cognitive Services, Search,
# Container Apps, Logic Apps, App Service.
#
# This is the sibling of AWS's _SENSITIVE_READ_OPERATIONS (secretsmanager:
# get_secret_value). The AWS side is a SET because "the thing that returns a
# secret" is never one call; the Azure side used to be a single hardcoded
# `microsoft.storage/storageaccounts` + `/listkeys` check, which left Cosmos DB
# keys, Event Hub keys, ACR credentials, App Service settings and publish
# profiles, storage SAS tokens, and Cognitive Services keys classified as
# ordinary writes — approvable at the gate, after which the secret lands in the
# chat transcript and the model's context.
#
# Blocked, not gated: a secret that reaches the transcript cannot be un-read.
_CREDENTIAL_ACTIONS = frozenset({
    "listkeys", "listsecrets", "listcredentials", "listconnectionstrings",
    "listaccountsas", "listservicesas", "listsas", "listquerykeys",
    "listadminkeys", "listauthkeys", "listclientsecret", "listcallbackurl",
    "listchannelwithkeys", "listserviceaccountcredential",
})

# App Service hides the same thing behind a nested path rather than an action verb.
_CREDENTIAL_PATH_TAILS = (
    "/config/appsettings/list",
    "/config/connectionstrings/list",
    "/publishxml",
)

# Rotating a credential is a different harm from reading one: it silently breaks
# every client still using the old key.
_CREDENTIAL_ROTATION_ACTIONS = frozenset({
    "regeneratekey", "regeneratecredential", "regenerateadminkey",
    "regeneratequerykey", "regenerateaccesskey",
})


def _check_credential_actions(method: str, path_l: str) -> Optional[OperationSafety]:
    """Block POST actions that return or rotate a live credential, in any namespace."""
    if method != "POST":
        return None

    tail = path_l.rstrip("/")
    action = tail.rsplit("/", 1)[-1]

    if action in _CREDENTIAL_ACTIONS or tail.endswith(_CREDENTIAL_PATH_TAILS):
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message=(
                "Reading live credentials is blocked — keys, connection strings, SAS "
                "tokens and publish profiles grant full data-plane access, and once "
                "returned they can't be un-read. Retrieve them from the Azure portal "
                "if you genuinely need them."
            ),
        )

    if action in _CREDENTIAL_ROTATION_ACTIONS:
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message=(
                "Regenerating a credential is blocked — it instantly breaks every "
                "client still using the old key. Rotate from the Azure portal if intended."
            ),
        )

    return None


def _check_blocked_azure(method: str, path_l: str, body) -> Optional[OperationSafety]:
    """Non-delete backdoor / credential / audit-blinding ops that a one-line gate
    must not be able to wave through. Returns a BLOCKED OperationSafety or None.

    Mirrors AWS BLOCKED_OPERATIONS, sibling-for-sibling per AZURE_SAFETY_SPEC.md
    Layer C. Deletes are already caught by Layer A, so this is only PUT/PATCH/POST.
    """
    props = _props(body)

    # Credential read / rotation — namespace-wide, checked before anything else.
    cred = _check_credential_actions(method, path_l)
    if cred:
        return cred

    # Defender for Cloud plan downgrade to Free = disabling threat detection.
    # (config:stop_configuration_recorder analog — a PUT, not a delete.)
    if "/providers/microsoft.security/pricings" in path_l and method in ("PUT", "PATCH"):
        tier = str(props.get("pricingtier", "")).strip().lower()
        if tier == "free":
            return OperationSafety(
                level=SafetyLevel.BLOCKED,
                message="Downgrading Microsoft Defender for Cloud to the Free tier is blocked — it "
                        "turns off threat detection. Change the plan in the Azure portal if intended.",
            )

    # Disabling security auto-provisioning = severing telemetry (guardduty:disassociate analog).
    if "/providers/microsoft.security/autoprovisioningsettings" in path_l and method in ("PUT", "PATCH"):
        if str(props.get("autoprovision", "")).strip().lower() == "off":
            return OperationSafety(
                level=SafetyLevel.BLOCKED,
                message="Disabling Defender auto-provisioning is blocked — it stops security telemetry "
                        "from being collected. Manage this in the Azure portal.",
            )

    # Storage account keys — sensitive credential read + credential rotation (POST actions).
    if "/providers/microsoft.storage/storageaccounts" in path_l:
        tail = path_l.rstrip("/")
        if method == "POST" and tail.endswith("/listkeys"):
            return OperationSafety(
                level=SafetyLevel.BLOCKED,
                message="Reading storage account access keys is blocked — they grant full data-plane "
                        "access and a known privilege-escalation path (like reading a secret's value).",
            )
        if method == "POST" and tail.endswith("/regeneratekey"):
            return OperationSafety(
                level=SafetyLevel.BLOCKED,
                message="Regenerating a storage account key is blocked — it can lock out or hijack "
                        "Shared-Key access. Rotate keys from the Azure portal if intended.",
            )

    # Key Vault access-policy grant (credential-heist enabler on access-policy vaults).
    if "/providers/microsoft.keyvault/vaults" in path_l:
        if method == "POST" and path_l.rstrip("/").endswith("/accesspolicies/add"):
            return OperationSafety(
                level=SafetyLevel.BLOCKED,
                message="Granting Key Vault access policies is blocked — it can hand out get-secret "
                        "rights. Manage vault access in the Azure portal (RBAC-model vaults route "
                        "through role assignment instead).",
            )
        if method in ("PUT", "PATCH"):
            aps = props.get("accesspolicies")
            if isinstance(aps, list) and aps:
                return OperationSafety(
                    level=SafetyLevel.BLOCKED,
                    message="Setting Key Vault access policies is blocked — it can grant get-secret "
                            "rights to a principal. Manage vault access in the Azure portal.",
                )

    # Scheduled/triggered code execution = persistence (events:put_rule analog).
    if "/providers/microsoft.automation/automationaccounts" in path_l and method in ("PUT", "PATCH"):
        if any(seg in path_l for seg in ("/runbooks/", "/webhooks/", "/schedules/")):
            return OperationSafety(
                level=SafetyLevel.BLOCKED,
                message="Creating Automation runbooks, webhooks, or schedules is blocked — scheduled/"
                        "triggered code execution is a persistence backdoor. Manage automation in the "
                        "Azure portal.",
            )
    if "/providers/microsoft.logic/workflows/" in path_l and method in ("PUT", "PATCH"):
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message="Creating Logic App workflows is blocked — triggered code execution is a "
                    "persistence backdoor. Build workflows in the Azure portal if intended.",
        )

    return None


# =============================================================================
# LAYER D — DANGEROUS_PATTERNS (conditional, parameter-inspecting)
# =============================================================================

def check_azure_patterns(method: str, path: str, body=None) -> PatternResult:
    """Conditional parameter checks — open ports, public storage, SQL firewall, etc.
    Only meaningful for writes; returns an empty PatternResult otherwise."""
    m = (method or "").strip().upper()
    if m not in ("PUT", "PATCH", "POST"):
        return PatternResult()
    p = _norm_path(path)
    props = _props(body)

    # Dispatch most-specific first (container/extension/action paths sit under broader ones).
    if "/networksecuritygroups" in p:
        return _check_nsg(props)

    if "/blobservices/default/containers/" in p or p.rstrip("/").endswith("/blobservices/default/containers"):
        return _check_container(props)

    if "/providers/microsoft.storage/storageaccounts" in p:
        return _check_storage_account(props)

    if "/providers/microsoft.sql/servers/" in p and "/firewallrules" in p:
        return _check_sql_firewall(props)

    if "/providers/microsoft.sql/servers/" in p:
        return _check_sql_server(props)

    if "/virtualmachines/" in p and "/extensions/" in p:
        return _check_vm_extension(props)

    if m == "POST" and p.rstrip("/").endswith("/runcommand"):
        return _check_run_command(props)

    if "/providers/microsoft.compute/virtualmachines/" in p and "/extensions/" not in p:
        return _check_vm(props)

    if "/providers/microsoft.compute/virtualmachinescalesets/" in p:
        return _check_vmss(_lower_keys(body) if isinstance(body, dict) else {})

    if "/networkinterfaces/" in p:
        return _check_nic(props)

    if m == "POST" and p.rstrip("/").endswith("/begingetaccess"):
        return _check_disk_export(props)

    return PatternResult()


def _source_is_world(rule: dict) -> bool:
    """True when an NSG rule's source is any of *, 0.0.0.0/0, or the Internet tag."""
    prefixes = []
    single = rule.get("sourceaddressprefix")
    if single is not None:
        prefixes.append(single)
    many = rule.get("sourceaddressprefixes")
    if isinstance(many, list):
        prefixes.extend(many)
    return any(str(t).strip().lower() in _WORLD_SOURCE_TOKENS for t in prefixes)


def _dest_ports(rule: dict):
    """All destination port range strings on an NSG rule."""
    out = []
    single = rule.get("destinationportrange")
    if single is not None:
        out.append(str(single))
    many = rule.get("destinationportranges")
    if isinstance(many, list):
        out.extend(str(x) for x in many)
    return out


def _check_nsg(props: dict) -> PatternResult:
    """Block inbound Allow rules from the world to sensitive ports / all ports."""
    rules = []
    sec_rules = props.get("securityrules")
    if isinstance(sec_rules, list):
        for r in sec_rules:
            if isinstance(r, dict):
                rp = r.get("properties")
                rules.append(rp if isinstance(rp, dict) else r)
    else:
        rules.append(props)  # a single securityRule PUT — properties are inline

    exposed = set()
    all_ports_world = False
    non_sensitive_world = False

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if str(rule.get("access", "")).strip().lower() != "allow":
            continue
        if str(rule.get("direction", "")).strip().lower() != "inbound":
            continue
        if not _source_is_world(rule):
            continue

        protocol = str(rule.get("protocol", "")).strip().lower()
        ports = _dest_ports(rule)

        # protocol "*" + port "*" (or no ports) = all traffic to the world.
        if protocol in ("*", "") and (not ports or any(pr.strip() == "*" for pr in ports)):
            all_ports_world = True
            continue

        for pr in ports:
            pr = pr.strip()
            if pr == "*":
                all_ports_world = True
                continue
            try:
                if "-" in pr:
                    lo, hi = pr.split("-", 1)
                    rng = range(int(lo), int(hi) + 1)
                else:
                    rng = [int(pr)]
                hit = _SENSITIVE_PORTS.intersection(rng)
                if hit:
                    exposed.update(hit)
                else:
                    non_sensitive_world = True
            except (ValueError, TypeError):
                # Unparseable port — treat as risky, warn.
                non_sensitive_world = True

    if all_ports_world:
        return PatternResult(
            blocked=True,
            message="Opening all ports/protocols to the internet (source *, 0.0.0.0/0, or Internet) "
                    "is blocked. Restrict the source to your VNet or a known IP.",
        )
    if exposed:
        return PatternResult(
            blocked=True,
            message=f"Opening ports {sorted(exposed)} to the internet is blocked — these are sensitive "
                    f"service ports (SSH, RDP, databases). Restrict the source to your VNet or a known IP.",
        )
    if non_sensitive_world:
        return PatternResult(
            warning="This NSG rule allows inbound traffic from the whole internet. Make sure that's intended.",
            exposure="open this port to the internet",
        )
    return PatternResult()


def _check_container(props: dict) -> PatternResult:
    """Block anonymous (public) blob container access."""
    access = str(props.get("publicaccess", "")).strip().lower()
    if access in ("blob", "container"):
        return PatternResult(
            blocked=True,
            message="Making a blob container publicly readable (publicAccess "
                    f"'{props.get('publicaccess')}') is blocked — anonymous read exposes its data. "
                    "Use SAS tokens or private access instead.",
        )
    return PatternResult()


def _check_storage_account(props: dict) -> PatternResult:
    """Block the account-level anonymous-access master switch; warn on firewall opens.

    The block stays. What changed is the SENTENCE, and that is not cosmetic.

    A hard block is the one message the model cannot argue with, so it is also the only
    place we get to teach. When this rule said only "keep it off and use SAS tokens or
    private access", a model asked to host a static site read that as "static hosting is
    not possible on Azure Storage", abandoned the correct primitive (Storage $web, ~$0.02
    a month, no compute quota) and fell back to an App Service Plan the subscription had
    no VM quota for. Eight and a half minutes, three plans, nothing deployed — caused
    entirely by a guardrail that was RIGHT and silent about the way through.

    It was right, too: the flag was never needed. Microsoft's own documentation is
    explicit that "disallowing anonymous access for a storage account does not affect any
    static websites hosted in that storage account. The $web container is always publicly
    accessible." So the safe path and the wanted outcome were the same path all along, and
    the only thing missing was saying so.

    The general rule this is an instance of: a hard block whose message does not name the
    allowed alternative is a bug. The model is the user's hands — a dead end does not
    stop a bad idea, it pushes the next one somewhere worse.
    """
    apba = props.get("allowblobpublicaccess")
    if apba is True or str(apba).strip().lower() == "true":
        return PatternResult(
            blocked=True,
            message="Enabling allowBlobPublicAccess is blocked — it permits anonymous public "
                    "access to blob containers. Set it to false. If you are hosting a static "
                    "website, you do not need this flag at all: the $web container is served "
                    "publicly by the static-website endpoint whether or not anonymous blob "
                    "access is allowed, so enable static website hosting on the account and "
                    "upload to $web. For anything else, use SAS tokens or private access.",
        )

    net = props.get("networkacls")
    if isinstance(net, dict) and str(net.get("defaultaction", "")).strip().lower() == "allow":
        return PatternResult(
            warning="This opens the storage account firewall to all networks (networkAcls "
                    "defaultAction=Allow). Restrict to selected networks if it holds private data.",
            exposure="open this storage account to all networks",
        )
    if str(props.get("publicnetworkaccess", "")).strip().lower() == "enabled":
        return PatternResult(
            warning="This enables public network access on the storage account. Make sure that's intended.",
            exposure="open this storage account to the internet",
        )
    return PatternResult()


def _check_sql_firewall(props: dict) -> PatternResult:
    """Block SQL firewall rules that expose the server to all Azure / the whole internet."""
    start = str(props.get("startipaddress", "")).strip()
    end = str(props.get("endipaddress", "")).strip()
    if start == "0.0.0.0" and end in ("0.0.0.0", "255.255.255.255"):
        which = "all Azure services" if end == "0.0.0.0" else "the entire internet"
        return PatternResult(
            blocked=True,
            message=f"This SQL firewall rule exposes the server to {which} (a documented brute-force "
                    "vector). Restrict startIpAddress/endIpAddress to a known IP range.",
        )
    return PatternResult()


_SQL_RESERVED_LOGINS = frozenset({
    "admin", "administrator", "sa", "root", "dbmanager", "loginmanager",
    "guest", "public", "azure_superuser", "azure_pgadmin",
})


def _check_sql_server(props: dict) -> PatternResult:
    """Block reserved admin logins (Azure SQL rejects them); warn on public access."""
    login = str(props.get("administratorlogin", "")).strip().lower()
    if login and login in _SQL_RESERVED_LOGINS:
        return PatternResult(
            blocked=True,
            message=f"'{props.get('administratorlogin')}' is a reserved Azure SQL admin login and the "
                    "create will fail. Choose a custom administrator login.",
        )
    if str(props.get("publicnetworkaccess", "")).strip().lower() == "enabled":
        return PatternResult(
            warning="This SQL server allows public network access. Ensure firewall rules restrict it appropriately.",
            exposure="open this database server to the internet",
        )
    return PatternResult()


def _scan_commands(candidates) -> Optional[str]:
    """Run each candidate command string through the shared sanitizer.
    Returns the block reason for the first unsafe command, else None."""
    from core.sanitizer import get_sanitizer
    sanitizer = get_sanitizer()
    for cmd in candidates:
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        safe, reason = sanitizer.is_safe_command(cmd)
        if not safe:
            return f"{reason} — command: {cmd[:80]}"
    return None


def _collect_strings(obj, out, depth=0):
    """Collect all string values from a nested structure (bounded depth)."""
    if depth > 6:
        return
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_strings(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _collect_strings(v, out, depth + 1)


def _check_vm_extension(props: dict) -> PatternResult:
    """CustomScript extension = arbitrary code as root/SYSTEM. Scan the script;
    block if unsafe, else warn (it's always-gated by the loop). Mirrors ssm_run_command."""
    ext_type = str(props.get("type", "")).strip().lower()
    settings = props.get("settings") if isinstance(props.get("settings"), dict) else {}
    protected = props.get("protectedsettings") if isinstance(props.get("protectedsettings"), dict) else {}

    is_custom_script = "customscript" in ext_type or "commandtoexecute" in settings or "commandtoexecute" in protected
    if not is_custom_script:
        return PatternResult()

    candidates = []
    _collect_strings(settings, candidates)
    _collect_strings(protected, candidates)
    reason = _scan_commands(candidates)
    if reason:
        return PatternResult(blocked=True, message=f"Blocked custom-script extension: {reason}")
    return PatternResult(
        warning="This installs a custom-script extension that runs commands as root/SYSTEM on the VM. "
                "Verify the script before approving.",
    )


def _check_run_command(props: dict) -> PatternResult:
    """VM runCommand = arbitrary code as root/SYSTEM. Scan the script; block if unsafe,
    else warn. Mirrors ssm_run_command exactly (always-gated + sanitizer scan)."""
    candidates = []
    source = props.get("source")
    if isinstance(source, dict):
        _collect_strings(source, candidates)
    _collect_strings(props.get("script", []), candidates)
    _collect_strings(props.get("parameters", []), candidates)
    reason = _scan_commands(candidates)
    if reason:
        return PatternResult(blocked=True, message=f"Blocked VM run-command: {reason}")
    return PatternResult(
        warning="This runs an arbitrary command as root/SYSTEM on the VM. Verify the command before approving.",
    )


def _check_vm(props: dict) -> PatternResult:
    """Warn on customData injection (boot script) and IP-forwarding. customData is a
    warn (not block): a raw ARM PUT can't tell first-create born-config from a modify
    of an existing VM, and born-config is legitimate — so it gates rather than blocks."""
    os_profile = props.get("osprofile")
    if isinstance(os_profile, dict) and os_profile.get("customdata"):
        return PatternResult(
            warning="This sets VM customData (a boot/startup script). On an existing VM this can inject "
                    "code — verify it's the intended configuration.",
        )
    return PatternResult()


def _check_vmss(lb_body: dict) -> PatternResult:
    """Cap scale-set instance count — the Azure analog of EC2 MaxCount."""
    sku = lb_body.get("sku") if isinstance(lb_body.get("sku"), dict) else {}
    capacity = sku.get("capacity")
    try:
        capacity = int(capacity)
    except (ValueError, TypeError):
        return PatternResult()
    if capacity > 20:
        return PatternResult(
            blocked=True,
            message=f"Scaling to {capacity} instances at once is blocked. Maximum is 20 via the generic executor.",
        )
    if capacity > 10:
        return PatternResult(
            warning=f"Scaling to {capacity} instances. This will incur significant charges.",
        )
    return PatternResult()


def _check_nic(props: dict) -> PatternResult:
    """Warn on IP forwarding — turns the VM into a router/pivot."""
    ipf = props.get("enableipforwarding")
    if ipf is True or str(ipf).strip().lower() == "true":
        return PatternResult(
            warning="Enabling IP forwarding lets this VM forward traffic (router/NAT behavior). "
                    "Verify this is intended.",
        )
    return PatternResult()


def _check_disk_export(props: dict) -> PatternResult:
    """Warn on disk/snapshot export (beginGetAccess returns a downloadable SAS URI)."""
    return PatternResult(
        warning="This exports the raw disk/snapshot bytes as a downloadable SAS URL (a data-exfiltration "
                "path). Make sure you intend to move this data out of the tenant.",
    )


# =============================================================================
# Always-gate classification (the "open ports" class — re-prompts every time)
# =============================================================================

# Path markers whose writes change security posture or grant access — they must
# re-prompt even inside an already-approved message, mirroring AWS _ALWAYS_GATE_OPS.
_ALWAYS_GATE_MARKERS = (
    "/providers/microsoft.authorization/roleassignments",  # RBAC grant (the built-in exception)
    "/networksecuritygroups",                              # NSG open-ports class
    "/firewallrules",                                      # SQL firewall exposure
    "/blobservices/default/containers",                    # blob container public access
    "/extensions/",                                        # custom-script extension (RCE)
    "/runcommand",                                         # VM run-command (RCE)
)


def azure_op_always_gates(method: str, path: str, body=None) -> bool:
    """True for the security-posture / access-grant / RCE class that must re-prompt
    every time, even under the one-yes-per-message approval. Azure analog of
    membership in loop.py:_ALWAYS_GATE_OPS."""
    p = _norm_path(path)
    if any(m in p for m in _ALWAYS_GATE_MARKERS):
        return True
    # Storage-account exposure toggles live in the body, not the path.
    if "/providers/microsoft.storage/storageaccounts" in p:
        return _storage_exposure_increases(_props(body))
    return False


def _is_true(v) -> bool:
    """ARM bodies carry booleans as real bools from Claude and as strings from raw
    JSON pasted by a user. Treat both alike."""
    return v is True or (isinstance(v, str) and v.strip().lower() == "true")


def _storage_exposure_increases(props: dict) -> bool:
    """True only when a storage-account write OPENS access, not merely mentions it.

    This used to fire on the mere PRESENCE of an exposure key, which had it exactly
    backwards. Born-safe makes the model set `allowBlobPublicAccess: false`,
    `publicNetworkAccess: "Disabled"` and a deny-by-default ACL unprompted — the
    safest possible body — and every one of those tripped the always-gate. The result
    was that the more securely Liberra built, the more times the user had to click:
    approve the resource group, then approve the storage account again, for one
    intent. Locking something down is not a posture change that needs re-approval;
    opening it is.

    Unknown/omitted values stay conservative: an ACL with no defaultAction reads as
    open, because that is ARM's own default.
    """
    if _is_true(props.get("allowblobpublicaccess")):
        return True

    pna = props.get("publicnetworkaccess")
    if isinstance(pna, str) and pna.strip().lower() == "enabled":
        return True

    acls = props.get("networkacls")
    if isinstance(acls, dict):
        default_action = str(acls.get("defaultaction", "Allow")).strip().lower()
        if default_action == "allow":
            return True

    return False


# =============================================================================
# Full Safety Check (combines all layers) — the single entry point
# =============================================================================

def full_safety_check_azure(
    method: str,
    path: str,
    api_version: Optional[str] = None,
    body=None,
) -> Tuple[OperationSafety, PatternResult]:
    """Run all Azure safety layers for one ARM call.

    The Azure sibling of full_safety_check(). Returns (OperationSafety, PatternResult)
    with the exact same shapes AWS returns, so loop.py:_classify_gate and the executor
    read them identically. api_version is accepted for signature symmetry with the tool
    (it never affects safety classification).
    """
    safety = classify_azure_operation(method, path, body)
    pattern = check_azure_patterns(method, path, body)
    return safety, pattern
