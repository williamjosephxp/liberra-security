# NOTE: This file is published verbatim from Liberra's backend
# (backend/guardrails/aws_safety.py). Nothing in this file has been redacted.
#
# It cannot be executed standalone -- it imports internal modules
# (knowledge.loader) that are not included here. The safety classification
# logic is complete and verifiable as-is.
#
# What this file is: every operation Liberra's AI attempts is classified here
# BEFORE it reaches AWS -- read / write / destructive / blocked. Blocked means
# it never executes. Writes pause for user approval in the agent loop.
#
# Last synced with production: 2026-07-07
# Source: https://liberraai.com
# Repository: https://github.com/williamjosephxp/liberra-security

"""
AWS Safety Layer — Generic Executor Guardrails

Provides safety classification, blocked operation enforcement, dangerous pattern
detection, service scoping, and method validation
for the generic AWS executor (aws_read + aws_execute).

This is the safety net. Nothing executes without passing through here.

Components:
1. SafetyLevel — classify any boto3 method as READ/WRITE/DESTRUCTIVE/BLOCKED
2. BLOCKED_OPERATIONS — hard deny list (derived from CloudFormation STANDARD tier)
3. DANGEROUS_PATTERNS — conditional blocks (SG 0.0.0.0/0, public S3, etc.)
4. NEVER_ALLOWED — block only account-level dangerous services, everything else allowed
5. validate_operation() — boto3 introspection (does method actually exist?)
"""

import re
import logging
import difflib
import boto3
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# A. Safety Level Classification
# =============================================================================

class SafetyLevel(str, Enum):
    """Safety level for a boto3 operation."""
    READ = "read"               # Auto-approve, no confirmation
    WRITE = "write"             # Requires confirmation
    DESTRUCTIVE = "destructive" # Requires confirmation + warning
    BLOCKED = "blocked"         # Hard deny, never execute


@dataclass
class OperationSafety:
    """Result of classifying a boto3 operation."""
    level: SafetyLevel
    message: str = ""
    cost_warning: Optional[str] = None
    confirmation_message: Optional[str] = None


# Method prefix → SafetyLevel
# IAM operations that bypass the blanket IAM write block and go to parameter inspection.
# These are allow/deny decided by _check_iam_policy_attach / _check_iam_policy_detach.
_IAM_PARAM_GATED_OPS: Set[str] = {"attach_role_policy", "detach_role_policy"}

# AWS-managed policies that can never be attached — grant excessive account-wide permissions.
# Everything else under arn:aws:iam::aws:policy/* is allowed (with canvas confirmation).
_BLOCKED_IAM_MANAGED_POLICIES: Set[str] = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/IAMAdminAccess",
    "arn:aws:iam::aws:policy/AWSOrganizationsFullAccess",
    "arn:aws:iam::aws:policy/AWSAccountManagementFullAccess",
}

_READ_PREFIXES = (
    "describe_", "list_", "get_", "head_", "check_",
    "batch_get_", "lookup_", "search_", "filter_",
    "can_paginate", "generate_presigned",
)

_WRITE_PREFIXES = (
    "create_", "put_", "update_", "modify_", "attach_",
    "associate_", "allocate_", "enable_", "register_",
    "tag_", "start_", "import_", "add_", "set_",
    "authorize_", "copy_", "reboot_", "run_", "send_",
)

_DESTRUCTIVE_PREFIXES = (
    "delete_", "terminate_", "remove_", "detach_",
    "disassociate_", "release_", "deregister_", "disable_",
    "stop_", "revoke_", "purge_", "unassign_", "untag_",
)

# Trust-phase: keyword-level hard block for all delete/terminate/purge ops.
# Catches every AWS service (current + future) without per-service enumeration.
# Specific security/backdoor blocks (EventBridge, SSM activation, etc.) remain in BLOCKED_OPERATIONS.
_DELETE_KEYWORDS: frozenset = frozenset({"delete", "terminate", "purge"})


def classify_operation(
    service: str,
    operation: str,
    parameters: Optional[dict] = None,
) -> OperationSafety:
    """
    Classify a boto3 operation by safety level.

    Checks blocked operations first, then classifies by method prefix.
    Unknown methods default to WRITE (fail-safe — requires confirmation).

    Args:
        service: AWS service name (e.g., "ec2", "s3")
        operation: boto3 method name (e.g., "describe_instances")
        parameters: Optional parameters (for cost warnings)

    Returns:
        OperationSafety with level, message, and optional warnings
    """
    # Normalize inputs — prevents case-bypass ("STS" slipping past lowercase "sts" check)
    service = service.strip().lower()

    # sts:get_caller_identity is a harmless read ("which account/identity am I?") — carve it
    # out of the blanket sts block. assume_role / get_session_token / get_federation_token
    # stay blocked by NEVER_ALLOWED below.
    if service == "sts" and operation.strip().lower() == "get_caller_identity":
        return OperationSafety(
            level=SafetyLevel.READ,
            message="Read operation: sts.get_caller_identity",
        )

    # 1. Check service scope — block only account-level dangerous services
    if service in NEVER_ALLOWED:
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message=f"Service '{service}' is blocked — account-level security risk.",
        )

    # 2. Normalize operation to lowercase for ALL checks (case-insensitive matching)
    op_lower = operation.lower()

    # 2b. Trust-phase: hard-block all delete/terminate/purge operations globally.
    # Simpler and more complete than per-service BLOCKED_OPERATIONS entries for deletions.
    if any(kw in op_lower for kw in _DELETE_KEYWORDS):
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message=f"'{service}.{operation}' is blocked — delete and terminate operations are currently disabled. Use the AWS console for resource removal.",
        )

    # 3. Check blocked operations (using lowercase to prevent case bypass)
    blocked_ops = BLOCKED_OPERATIONS.get(service, set())
    if op_lower in blocked_ops:
        custom_msg = BLOCKED_OPERATION_MESSAGES.get((service, op_lower))
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message=custom_msg or f"'{service}.{operation}' is blocked for safety. This operation is too destructive for the generic executor.",
        )

    # 4. Special case: IAM writes blocked — except param-gated ops which go to pattern checking.
    if service == "iam" and op_lower not in _IAM_PARAM_GATED_OPS:
        if not any(op_lower.startswith(p) for p in _READ_PREFIXES):
            return OperationSafety(
                level=SafetyLevel.BLOCKED,
                message="IAM write operations are blocked. Use curated IAM tools instead.",
            )

    # 4b. SSM Parameter Store: reads are free (including SecureString) — user consented on connect.
    # Writes confirmed, deletes blocked.
    if service == "ssm" and op_lower in ("get_parameter", "get_parameters", "get_parameters_by_path"):
        return OperationSafety(level=SafetyLevel.READ, message=f"Read operation: ssm.{operation}")

    if service == "ssm" and op_lower == "put_parameter":
        params = parameters or {}
        param_name = params.get("Name", "<unknown>")
        param_type = params.get("Type", "String")
        param_value = params.get("Value", "")

        if param_type == "SecureString":
            value_preview = "[SecureString — value hidden]"
        else:
            value_preview = (str(param_value)[:50] + "...") if len(str(param_value)) > 50 else str(param_value)

        confirmation_msg = (
            f"Store parameter '{param_name}' (Type: {param_type}, Value: {value_preview})"
        )

        logger.info(
            f"SSM put_parameter requested: name={param_name}, type={param_type}",
        )

        return OperationSafety(
            level=SafetyLevel.WRITE,
            message=f"Write operation: ssm.put_parameter ({param_name})",
            confirmation_message=confirmation_msg,
        )

    # 4c. Block sensitive read operations that expose secrets/credentials
    sensitive_key = (service, op_lower)
    if sensitive_key in _SENSITIVE_READ_OPERATIONS:
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message=f"'{service}.{operation}' is blocked — exposes sensitive data (secrets, credentials, keys).",
        )

    if any(op_lower.startswith(p) for p in _READ_PREFIXES):
        return OperationSafety(
            level=SafetyLevel.READ,
            message=f"Read operation: {service}.{operation}",
        )

    if any(op_lower.startswith(p) for p in _DESTRUCTIVE_PREFIXES):
        cost_warning = _get_cost_warning(service, operation)
        confirm_msg = (
            _CONFIRMATION_MESSAGES.get(f"{service}:{op_lower}")
            or f"Confirm destructive operation: {service}.{operation}"
        )
        return OperationSafety(
            level=SafetyLevel.DESTRUCTIVE,
            message=f"DESTRUCTIVE: {service}.{operation} — this may cause data loss or service disruption.",
            cost_warning=cost_warning,
            confirmation_message=confirm_msg,
        )

    if any(op_lower.startswith(p) for p in _WRITE_PREFIXES):
        cost_warning = _get_cost_warning(service, operation)
        confirm_msg = (
            _CONFIRMATION_MESSAGES.get(f"{service}:{op_lower}")
            or f"Confirm write operation: {service}.{operation}"
        )
        return OperationSafety(
            level=SafetyLevel.WRITE,
            message=f"Write operation: {service}.{operation}",
            cost_warning=cost_warning,
            confirmation_message=confirm_msg,
        )

    # 5. Unknown method — default to WRITE (fail-safe, requires confirmation)
    logger.warning(f"Unknown method prefix for {service}.{operation}, defaulting to WRITE")
    return OperationSafety(
        level=SafetyLevel.WRITE,
        message=f"Unknown operation type: {service}.{operation}. Treating as write (requires confirmation).",
        confirmation_message=f"Confirm operation: {service}.{operation}",
    )


# Sensitive read operations that expose secrets, credentials, or keys.
# These are classified as READ by prefix but BLOCKED for data safety.
_SENSITIVE_READ_OPERATIONS: Set[Tuple[str, str]] = {
    ("secretsmanager", "get_secret_value"),
    ("secretsmanager", "get_random_password"),
    # SSM handled separately above (allows /aws/service/* public params)
}


# =============================================================================
# B. Blocked Operations (derived from CloudFormation STANDARD tier deny list)
# =============================================================================
# Converted from IAM PascalCase → boto3 snake_case.
# Source: config/cloudformation_generator.py get_standard_permissions() lines 193-291
# This is a one-time conversion — maintained here, not parsed at runtime.

# Deletes/terminates are already blocked globally by _DELETE_KEYWORDS (step 3) and
# nuclear services by NEVER_ALLOWED (step 2) — so this list intentionally does NOT
# re-list them (that was ~140 lines of redundancy + IAM-policy duplication). It is
# ONLY the non-delete ops that create long-lived credentials, persistence/backdoors,
# or blind the audit & security substrate: nuclear-adjacent, not merely "destructive".
# A human approving a one-line gate shouldn't be able to wave these through.
#
# Everything NOT here (and not a delete/nuclear op) flows through the approval gate:
# the model proposes, the human approves. Code stops fighting the model.
BLOCKED_OPERATIONS: Dict[str, Set[str]] = {
    # Persistence / scheduled-automation backdoor
    "events": {"put_rule", "put_targets"},
    # Hybrid-activation backdoor — registers external machines as managed instances
    "ssm": {"create_activation"},
    # Catastrophic + irreversible. NOTE: "deletion" does NOT contain the substring
    # "delete", so _DELETE_KEYWORDS (step 3) misses this — it must stay listed here.
    "kms": {"schedule_key_deletion"},
    # Audit / security blinding — an attacker's first move
    "cloudtrail": {"stop_logging"},
    "guardduty": {
        "disassociate_members",
        "disassociate_from_master_account",
        "disassociate_from_administrator_account",
    },
    "config": {"stop_configuration_recorder"},
    # Identity / credential creation — long-lived creds + privilege escalation
    "iam": {
        "create_access_key",
        "create_login_profile",
        "create_user",
        "add_user_to_group",
    },
    # The iam entries get specific messages via BLOCKED_OPERATION_MESSAGES below.
}


# Per-operation messages for BLOCKED_OPERATIONS entries that need specific UX copy.
# Keyed by (service, boto3_snake_case_op). Falls back to generic message if absent.
BLOCKED_OPERATION_MESSAGES: Dict[Tuple[str, str], str] = {
    ("iam", "create_access_key"):   "Liberra cannot create long-term credentials. Use IAM roles with temporary credentials instead.",
    ("iam", "create_login_profile"): "Liberra cannot create console passwords. Manage console access through AWS IAM directly.",
    ("iam", "create_user"):         "Liberra cannot create IAM users. Use IAM Identity Center for user management.",
    ("iam", "add_user_to_group"):   "Liberra cannot modify group membership. This is a privilege escalation risk.",
}


# =============================================================================
# C. Dangerous Patterns (conditional blocks based on parameters)
# =============================================================================

@dataclass
class PatternResult:
    """Result of checking dangerous patterns."""
    blocked: bool = False
    warning: Optional[str] = None
    message: Optional[str] = None


# Ports that should never be open to 0.0.0.0/0
_SENSITIVE_PORTS = {22, 3389, 3306, 5432, 27017, 6379, 1433, 9200, 9300, 5439}


def check_dangerous_patterns(
    service: str,
    operation: str,
    parameters: Optional[dict] = None,
) -> PatternResult:
    """
    Check if an operation + parameters match known dangerous patterns.

    Returns PatternResult with blocked=True if the operation should be denied,
    or warning set if the operation is risky but allowed.
    """
    if not parameters:
        return PatternResult()

    key = f"{service}:{operation.lower()}"
    checker = _PATTERN_CHECKERS.get(key)
    if checker:
        return checker(parameters)

    return PatternResult()


def _check_sg_ingress(params: dict) -> PatternResult:
    """Block opening sensitive ports to 0.0.0.0/0 or ::/0, and all-traffic rules."""
    # Collect all (from_port, to_port, ip_protocol) tuples that are open to the world
    open_ranges = []

    # Flat parameter format
    cidr = params.get("CidrIp", "")
    cidr_ipv6 = params.get("CidrIpv6", "")
    if cidr == "0.0.0.0/0" or cidr_ipv6 == "::/0":
        open_ranges.append((
            params.get("FromPort"),
            params.get("ToPort"),
            str(params.get("IpProtocol", "")),
        ))

    # IpPermissions array format — check ALL entries, not just the first
    for perm in params.get("IpPermissions", []):
        perm_open = False
        for ip_range in perm.get("IpRanges", []):
            if ip_range.get("CidrIp") == "0.0.0.0/0":
                perm_open = True
                break
        if not perm_open:
            for ip_range in perm.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    perm_open = True
                    break
        if perm_open:
            open_ranges.append((
                perm.get("FromPort"),
                perm.get("ToPort"),
                str(perm.get("IpProtocol", "")),
            ))

    if not open_ranges:
        return PatternResult()

    # Check ALL open ranges for sensitive ports
    all_exposed = set()
    has_all_ports = False
    has_non_sensitive = False

    for from_port, to_port, ip_protocol in open_ranges:
        # IpProtocol "-1" means ALL traffic (all ports, all protocols) — block immediately
        if ip_protocol == "-1":
            has_all_ports = True
            continue

        # All ports open (FromPort=-1 or not specified)
        if from_port == -1 or (from_port is None and to_port is None):
            has_all_ports = True
            continue

        if from_port is not None and to_port is not None:
            try:
                port_range = range(int(from_port), int(to_port) + 1)
                exposed = _SENSITIVE_PORTS.intersection(port_range)
                all_exposed.update(exposed)
                if not exposed:
                    has_non_sensitive = True
            except (ValueError, TypeError):
                pass

    if has_all_ports:
        return PatternResult(
            blocked=True,
            message="Opening all ports/protocols to 0.0.0.0/0 is blocked.",
        )

    if all_exposed:
        return PatternResult(
            blocked=True,
            message=f"Opening ports {sorted(all_exposed)} to 0.0.0.0/0 is blocked. "
                    f"These are sensitive service ports (SSH, RDP, databases).",
        )

    if has_non_sensitive:
        # Find first non-protocol-all entry for the warning message
        for fp, tp, proto in open_ranges:
            if proto != "-1" and fp is not None and tp is not None:
                return PatternResult(
                    warning=f"Opening port {fp}-{tp} to 0.0.0.0/0. Ensure this is intended.",
                )

    return PatternResult()


def _check_s3_bucket_policy(params: dict) -> PatternResult:
    """Block public bucket policies (Principal: *)."""
    import json

    policy_raw = params.get("Policy", "")

    # Parse as JSON if string, or use dict directly
    policy_obj = None
    if isinstance(policy_raw, str) and policy_raw.strip():
        try:
            policy_obj = json.loads(policy_raw)
        except (json.JSONDecodeError, ValueError):
            pass
    elif isinstance(policy_raw, dict):
        policy_obj = policy_raw

    if policy_obj:
        # Walk the parsed policy for public principals
        for stmt in policy_obj.get("Statement", []):
            principal = stmt.get("Principal")
            # Direct wildcard: Principal: "*"
            if principal == "*":
                return PatternResult(
                    blocked=True,
                    message="Public bucket policies (Principal: *) are blocked. Use specific principals.",
                )
            # Array wildcard: Principal: ["*"]
            if isinstance(principal, list) and "*" in principal:
                return PatternResult(
                    blocked=True,
                    message="Public bucket policies (Principal: [*]) are blocked. Use specific principals.",
                )
            if isinstance(principal, dict):
                aws_val = principal.get("AWS")
                # Dict wildcard: Principal: {"AWS": "*"}
                if aws_val == "*":
                    return PatternResult(
                        blocked=True,
                        message="Public bucket policies (Principal: AWS:*) are blocked.",
                    )
                # Dict array wildcard: Principal: {"AWS": ["*"]}
                if isinstance(aws_val, list) and "*" in aws_val:
                    return PatternResult(
                        blocked=True,
                        message="Public bucket policies (Principal: AWS:[*]) are blocked.",
                    )

    # Fallback: string matching for non-JSON-parseable inputs
    policy_str = str(policy_raw)
    if '"Principal":"*"' in policy_str or '"Principal": "*"' in policy_str:
        return PatternResult(
            blocked=True,
            message="Public bucket policies (Principal: *) are blocked. Use specific principals.",
        )

    return PatternResult()


def _check_s3_bucket_acl(params: dict) -> PatternResult:
    """Block public bucket ACLs."""
    acl = params.get("ACL", "")
    if acl in ("public-read", "public-read-write", "authenticated-read"):
        return PatternResult(
            blocked=True,
            message=f"Public bucket ACL '{acl}' is blocked. Use bucket policies for fine-grained access.",
        )
    return PatternResult()


def _check_s3_public_access_block(params: dict) -> PatternResult:
    """Warn when disabling public access block."""
    config = params.get("PublicAccessBlockConfiguration", {})
    if isinstance(config, dict):
        disabled = [k for k, v in config.items() if v is False]
        if disabled:
            return PatternResult(
                warning=f"Disabling public access block settings: {', '.join(disabled)}. "
                        f"This may expose the bucket publicly.",
            )
    return PatternResult()


def _check_rds_delete(params: dict) -> PatternResult:
    """Block RDS deletion without final snapshot."""
    skip = params.get("SkipFinalSnapshot")
    snapshot_id = params.get("FinalDBSnapshotIdentifier")
    if skip is True and not snapshot_id:
        return PatternResult(
            blocked=True,
            message="RDS deletion without a final snapshot is blocked. "
                    "Set SkipFinalSnapshot=False or provide FinalDBSnapshotIdentifier.",
        )
    return PatternResult()


def _check_ec2_run_instances(params: dict) -> PatternResult:
    """Warn on large instance launches."""
    max_count = params.get("MaxCount", 1)
    try:
        max_count = int(max_count)
    except (ValueError, TypeError):
        max_count = 1

    if max_count > 20:
        return PatternResult(
            blocked=True,
            message=f"Launching {max_count} instances at once is blocked. Maximum is 20 via generic executor.",
        )
    if max_count > 10:
        return PatternResult(
            warning=f"Launching {max_count} instances. This will incur significant charges.",
        )
    return PatternResult()


_RDS_RESERVED_USERNAMES = frozenset({
    "admin", "administrator", "root", "rdsadmin", "master",
    "postgres", "mysql", "mariadb", "oracle",
    "sys", "system", "rds_superuser",
})


def _check_rds_create(params: dict) -> PatternResult:
    """Block reserved usernames and warn on public RDS instances."""
    master_user = params.get("MasterUsername", "")
    if master_user.lower() in _RDS_RESERVED_USERNAMES:
        return PatternResult(
            blocked=True,
            message=f"'{master_user}' is a reserved RDS username and will cause instance creation to fail. Use a custom username.",
        )
    if params.get("PubliclyAccessible") is True:
        return PatternResult(
            warning="Creating a publicly accessible RDS instance. "
                    "Ensure security groups restrict access appropriately.",
        )
    return PatternResult()


def _check_sg_egress(params: dict) -> PatternResult:
    """Block opening all egress to 0.0.0.0/0 with sensitive protocols."""
    # Same logic as ingress but for egress rules
    open_ranges = []

    cidr = params.get("CidrIp", "")
    cidr_ipv6 = params.get("CidrIpv6", "")
    if cidr == "0.0.0.0/0" or cidr_ipv6 == "::/0":
        open_ranges.append((
            params.get("FromPort"),
            params.get("ToPort"),
            str(params.get("IpProtocol", "")),
        ))

    for perm in params.get("IpPermissions", []):
        perm_open = False
        for ip_range in perm.get("IpRanges", []):
            if ip_range.get("CidrIp") == "0.0.0.0/0":
                perm_open = True
                break
        if not perm_open:
            for ip_range in perm.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    perm_open = True
                    break
        if perm_open:
            open_ranges.append((
                perm.get("FromPort"),
                perm.get("ToPort"),
                str(perm.get("IpProtocol", "")),
            ))

    if not open_ranges:
        return PatternResult()

    for from_port, to_port, ip_protocol in open_ranges:
        if ip_protocol == "-1":
            return PatternResult(
                warning="Opening all egress traffic to 0.0.0.0/0. This allows unrestricted outbound access.",
            )

    return PatternResult()


def _check_modify_instance_attribute(params: dict) -> PatternResult:
    """Block dangerous instance attribute modifications."""
    attr = params.get("Attribute", "")

    # UserData modification can inject startup scripts — very dangerous
    # Handles both old-style (Attribute="userData") and modern (UserData={...})
    if attr == "userData" or "UserData" in params:
        return PatternResult(
            blocked=True,
            message="Modifying instance UserData is blocked — can inject arbitrary startup scripts.",
        )

    # Instance type change: warn about ENA requirement for modern families
    if attr == "instanceType" or "InstanceType" in params:
        return PatternResult(
            warning="Verify ENA is enabled before changing to t3/m5/c5/r5/newer families — instance will fail to start if ENA is disabled.",
        )

    # Security group changes via generic executor should use curated sg tools
    if attr == "groupSet" or "Groups" in params:
        return PatternResult(
            warning="Changing instance security groups. Verify the new groups are correct.",
        )

    # Disabling termination protection weakens safety controls
    if attr == "disableApiTermination" or "DisableApiTermination" in params:
        disable_val = params.get("DisableApiTermination", {})
        # Modern API: DisableApiTermination={"Value": True/False}
        val = disable_val.get("Value") if isinstance(disable_val, dict) else disable_val
        if val is True or str(val).lower() == "true":
            return PatternResult(
                warning="Disabling termination protection. Instance can be terminated without this safeguard.",
            )

    # Disabling source/dest check enables network pivoting (NAT/router behavior)
    if attr == "sourceDestCheck" or "SourceDestCheck" in params:
        src_val = params.get("SourceDestCheck", {})
        val = src_val.get("Value") if isinstance(src_val, dict) else src_val
        if val is False or str(val).lower() == "false":
            return PatternResult(
                warning="Disabling source/dest check. Instance can forward traffic (NAT/router behavior).",
            )

    return PatternResult()


def _check_dynamodb_batch_write(params: dict) -> PatternResult:
    """Warn on large DynamoDB batch writes."""
    request_items = params.get("RequestItems", {})
    if not isinstance(request_items, dict):
        return PatternResult()
    total_ops = 0
    has_deletes = False
    for table_name, items in request_items.items():
        if isinstance(items, list):
            total_ops += len(items)
            for item in items:
                if "DeleteRequest" in item:
                    has_deletes = True

    if has_deletes and total_ops > 10:
        return PatternResult(
            warning=f"Batch write with {total_ops} operations including deletes across {len(request_items)} table(s). "
                    f"Verify this is intended.",
        )
    return PatternResult()


def _check_modify_sg_rules(params: dict) -> PatternResult:
    """Block widening existing SG rules to 0.0.0.0/0 via modify_security_group_rules."""
    sg_rules = params.get("SecurityGroupRules", [])
    if not isinstance(sg_rules, list):
        return PatternResult()
    for rule in sg_rules:
        if not isinstance(rule, dict):
            continue
        sg_rule = rule.get("SecurityGroupRule", {})
        if not isinstance(sg_rule, dict):
            continue
        cidr = sg_rule.get("CidrIpv4", "")
        cidr6 = sg_rule.get("CidrIpv6", "")
        proto = str(sg_rule.get("IpProtocol", ""))
        from_port = sg_rule.get("FromPort")
        to_port = sg_rule.get("ToPort")

        if cidr != "0.0.0.0/0" and cidr6 != "::/0":
            continue

        # All traffic
        if proto == "-1":
            return PatternResult(
                blocked=True,
                message="Modifying SG rule to allow all traffic from 0.0.0.0/0 is blocked.",
            )
        # Sensitive ports
        if from_port is not None and to_port is not None:
            try:
                port_range = range(int(from_port), int(to_port) + 1)
                exposed = _SENSITIVE_PORTS.intersection(port_range)
                if exposed:
                    return PatternResult(
                        blocked=True,
                        message=f"Modifying SG rule to open ports {sorted(exposed)} to 0.0.0.0/0 is blocked.",
                    )
            except (ValueError, TypeError):
                pass
    return PatternResult()


def _check_ec2_create_route(params: dict) -> PatternResult:
    """Warn on routes to 0.0.0.0/0 that aren't to IGW or NAT."""
    dest = params.get("DestinationCidrBlock", "")
    gw = params.get("GatewayId", "")
    nat = params.get("NatGatewayId", "")
    if dest == "0.0.0.0/0" and not gw and not nat:
        return PatternResult(
            warning="Route to 0.0.0.0/0 without an internet gateway or NAT gateway. Verify this is intended.",
        )
    return PatternResult()


def _check_ssm_send_command(params: dict) -> PatternResult:
    """Check SSM send_command for dangerous commands, blast radius, and document name."""
    # 0. Validate DocumentName — warn on non-standard documents
    doc_name = params.get("DocumentName", "AWS-RunShellScript")
    if doc_name not in ("AWS-RunShellScript", "AWS-RunPowerShellScript"):
        return PatternResult(
            warning=f"Non-standard SSM document: {doc_name}. Verify this is intended.",
        )

    # 1. Check command safety
    commands = []
    parameters = params.get("Parameters", {})
    if isinstance(parameters, dict):
        commands = parameters.get("commands", [])
    if not isinstance(commands, list):
        commands = []

    for cmd in commands:
        if not isinstance(cmd, str):
            continue
        # Lazy import to avoid circular dependency
        from core.sanitizer import get_sanitizer
        safe, reason = get_sanitizer().is_safe_command(cmd)
        if not safe:
            return PatternResult(
                blocked=True,
                message=f"Blocked: {reason} — command: {cmd[:80]}",
            )

    # 2. Check instance count (blast radius)
    instance_ids = params.get("InstanceIds", [])
    if isinstance(instance_ids, list) and len(instance_ids) > 20:
        return PatternResult(
            blocked=True,
            message=f"Sending command to {len(instance_ids)} instances is blocked. Maximum is 20 via generic executor.",
        )
    if isinstance(instance_ids, list) and len(instance_ids) > 5:
        return PatternResult(
            warning=f"Sending command to {len(instance_ids)} instances. Verify this is intended.",
        )

    # 3. Check tag-based targeting (unbounded blast radius)
    targets = params.get("Targets", [])
    if targets:
        return PatternResult(
            warning="Tag-based targeting may affect an unbounded number of instances. Verify targets carefully.",
        )

    return PatternResult()


# Destructive SSM Automation documents — hard deny list
_BLOCKED_AUTOMATION_DOCS = {
    "AWS-TerminateEC2Instance",
    "AWS-DeleteImage",
    "AWS-DeleteSnapshot",
    "AWS-DeleteCloudFormation",
    "AWS-DeleteEBSVolumeSnapshots",
}


def _check_ssm_automation(params: dict) -> PatternResult:
    """Check SSM start_automation_execution for destructive automation docs and blast radius."""
    doc_name = params.get("DocumentName", "")

    if doc_name in _BLOCKED_AUTOMATION_DOCS:
        return PatternResult(
            blocked=True,
            message=f"Blocked: SSM Automation document '{doc_name}' is destructive and not allowed via generic executor.",
        )

    # Warn on tag-based targeting (unbounded blast radius)
    targets = params.get("Targets", [])
    if targets:
        return PatternResult(
            warning="Tag-based targeting may affect an unbounded number of resources. Verify targets carefully.",
        )

    return PatternResult()


def _check_iam_policy_attach(params: dict) -> PatternResult:
    """Allow AWS-managed policies only; block custom ARNs and nuclear managed policies."""
    policy_arn = params.get("PolicyArn", "")
    if not policy_arn.startswith("arn:aws:iam::aws:policy/"):
        return PatternResult(
            blocked=True,
            message="Only AWS-managed policies can be attached via Liberra. "
                    "Custom policy attachment requires IAM console access.",
        )
    if policy_arn in _BLOCKED_IAM_MANAGED_POLICIES:
        policy_name = policy_arn.split("/")[-1]
        return PatternResult(
            blocked=True,
            message=f"'{policy_name}' cannot be attached — grants excessive account-wide permissions.",
        )
    return PatternResult()


def _check_iam_policy_detach(params: dict) -> PatternResult:
    """Detaching reduces access — allow any valid ARN."""
    if not params.get("PolicyArn"):
        return PatternResult(blocked=True, message="PolicyArn is required.")
    return PatternResult()


# Pattern checker dispatch table
_PATTERN_CHECKERS = {
    "ec2:authorize_security_group_ingress": _check_sg_ingress,
    "ec2:authorize_security_group_egress": _check_sg_egress,
    "ec2:run_instances": _check_ec2_run_instances,
    "ec2:create_route": _check_ec2_create_route,
    "ec2:modify_instance_attribute": _check_modify_instance_attribute,
    "ec2:modify_security_group_rules": _check_modify_sg_rules,
    "s3:put_bucket_policy": _check_s3_bucket_policy,
    "s3:put_bucket_acl": _check_s3_bucket_acl,
    "s3:put_public_access_block": _check_s3_public_access_block,
    "rds:delete_db_instance": _check_rds_delete,
    "rds:create_db_instance": _check_rds_create,
    "dynamodb:batch_write_item": _check_dynamodb_batch_write,
    "ssm:send_command": _check_ssm_send_command,
    "ssm:start_automation_execution": _check_ssm_automation,
    "iam:attach_role_policy": _check_iam_policy_attach,
    "iam:detach_role_policy": _check_iam_policy_detach,
}


# =============================================================================
# D. Service Scope
# =============================================================================

# FLIPPED: Block only what can nuke an account. Everything else is allowed.
# Individual dangerous OPERATIONS are blocked in BLOCKED_OPERATIONS above.
# Writes go through the confirmation gate. Reads auto-approve.
ALLOWED_SERVICES = None  # No allowlist — everything not in NEVER_ALLOWED is allowed

NEVER_ALLOWED: Set[str] = {
    "organizations",    # Can remove accounts from org
    "sts",              # Can assume any role, privilege escalation
    "account",          # Can close the entire AWS account
    "sso",              # Can grant org-wide access
    "sso-admin",        # Can manage SSO permissions
    "identitystore",    # Can modify identity federation
}


# =============================================================================
# E. Method Validation (boto3 introspection)
# =============================================================================

# Cache for validated service clients (service_name → set of valid methods)
_method_cache: Dict[str, Set[str]] = {}


def validate_operation(service: str, operation: str) -> Tuple[bool, str]:
    """
    Validate that a boto3 method exists for the given service.

    Uses boto3 introspection to check if the method exists on the client.
    Provides fuzzy-match suggestions for close method names.

    Args:
        service: AWS service name
        operation: boto3 method name

    Returns:
        (valid, error_message) — valid=True if method exists
    """
    try:
        methods = _get_service_methods(service)
    except Exception as e:
        return False, f"Invalid service '{service}': {e}"

    if operation in methods:
        return True, ""

    # Fuzzy match for suggestions
    close = difflib.get_close_matches(operation, sorted(methods), n=3, cutoff=0.6)
    suggestion = f" Did you mean: {', '.join(close)}?" if close else ""
    return False, f"'{operation}' is not a valid {service} operation.{suggestion}"


def _get_service_methods(service: str) -> Set[str]:
    """Get valid method names for a boto3 service (cached)."""
    if service not in _method_cache:
        try:
            # Create a dummy client for introspection (no real calls made)
            client = boto3.client(service, region_name="us-east-1",
                                  aws_access_key_id="dummy",
                                  aws_secret_access_key="dummy")
            # Get public methods (exclude private + meta)
            methods = {
                m for m in dir(client)
                if not m.startswith("_")
                and callable(getattr(client, m, None))
                and m not in ("meta", "exceptions", "waiter_names",
                              "can_paginate", "get_paginator", "get_waiter",
                              "close")
            }
            _method_cache[service] = methods
        except Exception:
            raise ValueError(f"'{service}' is not a valid AWS service")
    return _method_cache[service]


# =============================================================================
# F. Cost Warnings
# =============================================================================

_COST_WARNINGS: Dict[str, str] = {
    "ec2:run_instances": "EC2 instances incur hourly charges.",
    "rds:create_db_instance": "RDS instances run 24/7. Minimum ~$12/month.",
    "ec2:create_nat_gateway": "NAT Gateways cost ~$32/month + data transfer fees.",
    "elbv2:create_load_balancer": "ALB minimum ~$16/month + LCU charges.",
    "elasticache:create_cache_cluster": "ElastiCache nodes run 24/7.",
    "ec2:allocate_address": "Unused Elastic IPs cost ~$3.60/month.",
    "rds:create_db_cluster": "RDS clusters run 24/7 with multiple instances.",
    "ecs:create_service": "ECS services run tasks continuously.",
    "cloudfront:create_distribution": "CloudFront charges per request + data transfer.",
    "dynamodb:create_table": "DynamoDB charges for read/write capacity.",
    # Paid security services — always-on subscriptions, charged per resource/month
    "inspector2:enable": "AWS Inspector costs ~$1.18/instance/month for EC2 scanning. Billing starts immediately for every enabled instance.",
    "inspector2:enable_delegated_admin_account": "AWS Inspector costs ~$1.18/instance/month. Enabling org-wide delegation applies to all accounts.",
    "guardduty:create_detector": "AWS GuardDuty costs ~$4/instance/month for threat detection. Billing starts immediately.",
    "guardduty:create_members": "GuardDuty member accounts each incur ~$4/instance/month.",
    "macie2:enable_macie": "AWS Macie costs ~$1/GB of S3 data scanned per month. Billing starts on enablement.",
    "macie2:enable_organization_admin_account": "AWS Macie org-wide enablement — costs apply to all member accounts (~$1/GB scanned).",
    "securityhub:enable_security_hub": "AWS Security Hub costs ~$0.001 per security finding ingested per month.",
    "wafv2:create_web_acl": "AWS WAF costs ~$5/web ACL/month + $1 per million requests processed.",
    "shield:create_subscription": "AWS Shield Advanced costs $3,000/month minimum. This is a major financial commitment.",
    "config:put_configuration_recorder": "AWS Config costs $0.003 per configuration item recorded. High-change environments can accumulate significant costs.",
    "config:start_configuration_recorder": "AWS Config costs $0.003 per configuration item recorded.",
    "ce:create_cost_category_definition": "Cost Explorer API calls cost $0.01 each.",
}

# Extend with cost warnings from service knowledge files
try:
    from knowledge.loader import get_registry_extensions
    _, _, _ext_costs = get_registry_extensions()
    _COST_WARNINGS.update(_ext_costs)
except Exception:
    pass  # Safety layer works with built-in warnings only


def _get_cost_warning(service: str, operation: str) -> Optional[str]:
    """Get cost warning for an operation, if applicable."""
    return _COST_WARNINGS.get(f"{service}:{operation}")


# =============================================================================
# F2. Confirmation Messages (per-operation overrides)
# =============================================================================

# Rich confirmation messages for operations where the generic message
# ("Confirm write operation: ec2.stop_instances") loses critical context.
# Keyed as "service:operation" (lowercase). Looked up in classify_operation().
_CONFIRMATION_MESSAGES: Dict[str, str] = {
    "ec2:stop_instances": (
        "Stopping instances interrupts running workloads. "
        "Stopped instances still incur EBS storage costs."
    ),
    "ec2:terminate_instances": (
        "⚠️ PERMANENTLY destroys instances and all local storage. Cannot be undone."
    ),
    "ec2:reboot_instances": (
        "Rebooting instances causes ~1-2 minutes of downtime."
    ),
    "rds:stop_db_instance": (
        "AWS auto-restarts stopped RDS instances after 7 days — this is AWS-enforced. "
        "Data is preserved but storage charges continue."
    ),
    "rds:modify_db_instance": (
        "RDS modifications may cause a brief outage on single-AZ instances."
    ),
}


# =============================================================================
# G. Full Safety Check (combines all layers)
# =============================================================================

def full_safety_check(
    service: str,
    operation: str,
    parameters: Optional[dict] = None,
) -> Tuple[OperationSafety, PatternResult]:
    """
    Run all safety checks for a generic executor operation.

    Returns:
        (safety, pattern_result)
        - safety: OperationSafety from classify_operation
        - pattern_result: PatternResult from check_dangerous_patterns
    """
    safety = classify_operation(service, operation, parameters)
    pattern = check_dangerous_patterns(service, operation, parameters)

    return safety, pattern
