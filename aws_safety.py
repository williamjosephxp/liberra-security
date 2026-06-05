# This file is published for transparency.
#
# Cost warnings, confirmation messages, and boto3 method validation are not shown here.
# They are application logic, not safety logic.
# Everything that blocks or gates an AWS operation is shown in full, nothing redacted.
#
# Source: https://liberra.ai
# Repository: https://github.com/williamjosephxp/liberra-security

"""
AWS Safety Layer

Every boto3 operation passes through this file before reaching AWS.
Nothing executes without clearing these checks.

1. NEVER_ALLOWED     — six services blocked entirely, no operation ever
2. _DELETE_KEYWORDS  — universal block: any op containing delete/terminate/purge
3. BLOCKED_OPERATIONS — named operations blocked for security/backdoor reasons
4. DANGEROUS_PATTERNS — parameter-level blocks (open ports, public S3, etc.)
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Safety levels
# =============================================================================

class SafetyLevel(str, Enum):
    READ        = "read"        # Free — no confirmation needed
    WRITE       = "write"       # Requires user confirmation
    DESTRUCTIVE = "destructive" # Requires user confirmation
    BLOCKED     = "blocked"     # Hard deny — never executes


@dataclass
class OperationSafety:
    level: SafetyLevel
    message: str = ""


# =============================================================================
# Services blocked entirely
# No operation on these services ever executes, regardless of what is requested.
# =============================================================================

NEVER_ALLOWED: Set[str] = {
    "organizations",  # Can remove accounts from your AWS Organization
    "sts",            # Can assume arbitrary roles — privilege escalation
    "account",        # Can close your entire AWS account
    "sso",            # Can grant org-wide access
    "sso-admin",      # Can manage SSO permission sets
    "identitystore",  # Can modify identity federation
}


# =============================================================================
# Universal keyword block
#
# Any boto3 method name containing "delete", "terminate", or "purge" is
# immediately classified as BLOCKED — before any other check runs.
#
# This covers every AWS service, current and future, without enumeration.
# eks.delete_cluster, elasticache.delete_replication_group, emr.terminate_job_flows,
# lightsail.delete_instance — all blocked by this single check.
# =============================================================================

_DELETE_KEYWORDS: frozenset = frozenset({"delete", "terminate", "purge"})


# =============================================================================
# Method prefix classification
# =============================================================================

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


# =============================================================================
# IAM attachment constraints
# The only two IAM write operations allowed — with parameter-level checks below.
# =============================================================================

_IAM_PARAM_GATED_OPS: Set[str] = {"attach_role_policy", "detach_role_policy"}

_BLOCKED_IAM_MANAGED_POLICIES: Set[str] = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/IAMAdminAccess",
    "arn:aws:iam::aws:policy/AWSOrganizationsFullAccess",
    "arn:aws:iam::aws:policy/AWSAccountManagementFullAccess",
}


# =============================================================================
# Reads blocked for data exposure
# These look like reads by prefix but expose secrets or credentials.
# =============================================================================

_SENSITIVE_READ_OPERATIONS: Set[Tuple[str, str]] = {
    ("secretsmanager", "get_secret_value"),
    ("secretsmanager", "get_random_password"),
}


# =============================================================================
# classify_operation
# Called for every operation. Returns the safety level.
# Unknown methods default to WRITE — fail-safe, requires confirmation.
# =============================================================================

def classify_operation(
    service: str,
    operation: str,
    parameters: Optional[dict] = None,
) -> OperationSafety:
    # Normalize — prevents case-bypass ("STS" slipping past "sts" check)
    service = service.strip().lower()

    # 1. Block nuclear services entirely
    if service in NEVER_ALLOWED:
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message=f"Service '{service}' is blocked — account-level security risk.",
        )

    op_lower = operation.lower()

    # 2. Universal keyword block — delete/terminate/purge on any service
    if any(kw in op_lower for kw in _DELETE_KEYWORDS):
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message=f"'{service}.{operation}' is blocked — delete and terminate operations are disabled.",
        )

    # 3. Named blocked operations — security and backdoor risks
    blocked_ops = BLOCKED_OPERATIONS.get(service, set())
    if op_lower in blocked_ops:
        custom_msg = BLOCKED_OPERATION_MESSAGES.get((service, op_lower))
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message=custom_msg or f"'{service}.{operation}' is blocked.",
        )

    # 4. IAM: all writes blocked except attach/detach role policy (param-checked below)
    if service == "iam" and op_lower not in _IAM_PARAM_GATED_OPS:
        if not any(op_lower.startswith(p) for p in _READ_PREFIXES):
            return OperationSafety(
                level=SafetyLevel.BLOCKED,
                message="IAM write operations are blocked.",
            )

    # 5. SSM Parameter Store: reads free, writes confirmed
    if service == "ssm" and op_lower in ("get_parameter", "get_parameters", "get_parameters_by_path"):
        return OperationSafety(level=SafetyLevel.READ, message=f"Read: ssm.{operation}")

    if service == "ssm" and op_lower == "put_parameter":
        return OperationSafety(level=SafetyLevel.WRITE, message="Write: ssm.put_parameter")

    # 6. Block reads that expose secrets or credentials
    if (service, op_lower) in _SENSITIVE_READ_OPERATIONS:
        return OperationSafety(
            level=SafetyLevel.BLOCKED,
            message=f"'{service}.{operation}' is blocked — exposes sensitive data.",
        )

    # 7. Classify by method prefix
    if any(op_lower.startswith(p) for p in _READ_PREFIXES):
        return OperationSafety(level=SafetyLevel.READ, message=f"Read: {service}.{operation}")

    if any(op_lower.startswith(p) for p in _DESTRUCTIVE_PREFIXES):
        return OperationSafety(
            level=SafetyLevel.DESTRUCTIVE,
            message=f"Destructive: {service}.{operation} — requires confirmation.",
        )

    if any(op_lower.startswith(p) for p in _WRITE_PREFIXES):
        return OperationSafety(
            level=SafetyLevel.WRITE,
            message=f"Write: {service}.{operation} — requires confirmation.",
        )

    # 8. Unknown — fail-safe, treat as write, requires confirmation
    return OperationSafety(
        level=SafetyLevel.WRITE,
        message=f"Unknown operation: {service}.{operation}. Treating as write.",
    )


# =============================================================================
# Named blocked operations
#
# These are blocked because they create backdoors, enable persistent automation,
# or destroy security visibility — not because of delete/terminate naming.
# The delete/terminate/purge variants of these are already caught by the
# keyword block above.
# =============================================================================

BLOCKED_OPERATIONS: Dict[str, Set[str]] = {
    "lambda": {
        "invoke",       # Arbitrary code execution
        "invoke_async", # Same risk — deprecated but still works
    },
    "events": {
        "put_rule",    # Creates persistent scheduled automation — backdoor risk
        "put_targets", # Attaches targets to rules (can invoke Lambda, etc.)
    },
    "ssm": {
        "create_activation", # Registers external machines into your SSM fleet
        "create_association", # Creates persistent scheduled commands on instances
        "create_document",    # Stores reusable automation scripts
    },
    "cloudtrail": {
        "stop_logging", # Silences audit trail — attacker's first move
    },
    "guardduty": {
        "disassociate_members",
        "disassociate_from_master_account",
        "disassociate_from_administrator_account",
    },
    "config": {
        "stop_configuration_recorder", # Pauses compliance tracking
    },
    "iam": {
        # These four are blocked in addition to the IAM blanket write block above.
        # Listed separately to provide specific error messages.
        "create_access_key",   # Long-lived credentials — theft risk
        "create_login_profile", # Console password — expands attack surface
        "create_user",          # New identity — out of scope
        "add_user_to_group",    # Privilege escalation vector
    },
}

BLOCKED_OPERATION_MESSAGES: Dict[Tuple[str, str], str] = {
    ("iam", "create_access_key"):    "Liberra cannot create long-term credentials. Use IAM roles with temporary credentials instead.",
    ("iam", "create_login_profile"): "Liberra cannot create console passwords. Manage console access through AWS IAM directly.",
    ("iam", "create_user"):          "Liberra cannot create IAM users. Use IAM Identity Center for user management.",
    ("iam", "add_user_to_group"):    "Liberra cannot modify group membership. This is a privilege escalation risk.",
}


# =============================================================================
# Dangerous pattern checks
#
# These fire on specific parameter combinations regardless of the operation name.
# A write operation that passes the blocks above can still be denied here
# based on what it is actually trying to do.
# =============================================================================

@dataclass
class PatternResult:
    blocked: bool = False
    warning: Optional[str] = None
    message: Optional[str] = None


_SENSITIVE_PORTS = {22, 3389, 3306, 5432, 27017, 6379, 1433, 9200, 9300, 5439}


def check_dangerous_patterns(
    service: str,
    operation: str,
    parameters: Optional[dict] = None,
) -> PatternResult:
    if not parameters:
        return PatternResult()
    checker = _PATTERN_CHECKERS.get(f"{service}:{operation.lower()}")
    if checker:
        return checker(parameters)
    return PatternResult()


def _check_sg_ingress(params: dict) -> PatternResult:
    """Block opening sensitive ports or all traffic to 0.0.0.0/0."""
    open_ranges = []

    cidr = params.get("CidrIp", "")
    cidr_ipv6 = params.get("CidrIpv6", "")
    if cidr == "0.0.0.0/0" or cidr_ipv6 == "::/0":
        open_ranges.append((params.get("FromPort"), params.get("ToPort"), str(params.get("IpProtocol", ""))))

    for perm in params.get("IpPermissions", []):
        perm_open = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
        if not perm_open:
            perm_open = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
        if perm_open:
            open_ranges.append((perm.get("FromPort"), perm.get("ToPort"), str(perm.get("IpProtocol", ""))))

    if not open_ranges:
        return PatternResult()

    all_exposed = set()
    has_all_ports = False

    for from_port, to_port, ip_protocol in open_ranges:
        if ip_protocol == "-1" or from_port == -1 or (from_port is None and to_port is None):
            has_all_ports = True
            continue
        if from_port is not None and to_port is not None:
            try:
                exposed = _SENSITIVE_PORTS.intersection(range(int(from_port), int(to_port) + 1))
                all_exposed.update(exposed)
            except (ValueError, TypeError):
                pass

    if has_all_ports:
        return PatternResult(blocked=True, message="Opening all ports to 0.0.0.0/0 is blocked.")
    if all_exposed:
        return PatternResult(
            blocked=True,
            message=f"Opening ports {sorted(all_exposed)} to 0.0.0.0/0 is blocked. These are sensitive service ports.",
        )
    return PatternResult(warning="Opening a port to 0.0.0.0/0. Ensure this is intended.")


def _check_sg_egress(params: dict) -> PatternResult:
    """Warn on all-traffic egress to 0.0.0.0/0."""
    open_ranges = []

    cidr = params.get("CidrIp", "")
    if cidr == "0.0.0.0/0":
        open_ranges.append(str(params.get("IpProtocol", "")))

    for perm in params.get("IpPermissions", []):
        if any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])):
            open_ranges.append(str(perm.get("IpProtocol", "")))

    if any(p == "-1" for p in open_ranges):
        return PatternResult(warning="Opening all egress traffic to 0.0.0.0/0. This allows unrestricted outbound access.")
    return PatternResult()


def _check_s3_bucket_policy(params: dict) -> PatternResult:
    """Block public bucket policies (Principal: *)."""
    import json
    policy_raw = params.get("Policy", "")
    policy_obj = None
    if isinstance(policy_raw, str) and policy_raw.strip():
        try:
            policy_obj = json.loads(policy_raw)
        except (json.JSONDecodeError, ValueError):
            pass
    elif isinstance(policy_raw, dict):
        policy_obj = policy_raw

    if policy_obj:
        for stmt in policy_obj.get("Statement", []):
            principal = stmt.get("Principal")
            if principal == "*":
                return PatternResult(blocked=True, message="Public bucket policies (Principal: *) are blocked.")
            if isinstance(principal, list) and "*" in principal:
                return PatternResult(blocked=True, message="Public bucket policies (Principal: *) are blocked.")
            if isinstance(principal, dict):
                aws_val = principal.get("AWS")
                if aws_val == "*" or (isinstance(aws_val, list) and "*" in aws_val):
                    return PatternResult(blocked=True, message="Public bucket policies (Principal: AWS:*) are blocked.")

    if '"Principal":"*"' in str(policy_raw) or '"Principal": "*"' in str(policy_raw):
        return PatternResult(blocked=True, message="Public bucket policies (Principal: *) are blocked.")
    return PatternResult()


def _check_s3_bucket_acl(params: dict) -> PatternResult:
    """Block public bucket ACLs."""
    acl = params.get("ACL", "")
    if acl in ("public-read", "public-read-write", "authenticated-read"):
        return PatternResult(blocked=True, message=f"Public bucket ACL '{acl}' is blocked.")
    return PatternResult()


def _check_s3_public_access_block(params: dict) -> PatternResult:
    """Warn when disabling public access block."""
    config = params.get("PublicAccessBlockConfiguration", {})
    if isinstance(config, dict):
        disabled = [k for k, v in config.items() if v is False]
        if disabled:
            return PatternResult(warning=f"Disabling public access block settings: {', '.join(disabled)}.")
    return PatternResult()


def _check_rds_delete(params: dict) -> PatternResult:
    """Block RDS deletion without a final snapshot."""
    if params.get("SkipFinalSnapshot") is True and not params.get("FinalDBSnapshotIdentifier"):
        return PatternResult(
            blocked=True,
            message="RDS deletion without a final snapshot is blocked. Set SkipFinalSnapshot=False or provide FinalDBSnapshotIdentifier.",
        )
    return PatternResult()


def _check_rds_create(params: dict) -> PatternResult:
    """Block reserved usernames. Warn on publicly accessible instances."""
    _RESERVED = frozenset({
        "admin", "administrator", "root", "rdsadmin", "master",
        "postgres", "mysql", "mariadb", "oracle", "sys", "system", "rds_superuser",
    })
    if params.get("MasterUsername", "").lower() in _RESERVED:
        return PatternResult(
            blocked=True,
            message=f"'{params['MasterUsername']}' is a reserved RDS username. Use a custom username.",
        )
    if params.get("PubliclyAccessible") is True:
        return PatternResult(warning="Creating a publicly accessible RDS instance.")
    return PatternResult()


def _check_ec2_run_instances(params: dict) -> PatternResult:
    """Block launching more than 20 instances at once."""
    try:
        max_count = int(params.get("MaxCount", 1))
    except (ValueError, TypeError):
        max_count = 1
    if max_count > 20:
        return PatternResult(blocked=True, message=f"Launching {max_count} instances at once is blocked. Maximum is 20.")
    if max_count > 10:
        return PatternResult(warning=f"Launching {max_count} instances. This will incur significant charges.")
    return PatternResult()


def _check_modify_instance_attribute(params: dict) -> PatternResult:
    """Block UserData injection. Warn on type/SG changes."""
    attr = params.get("Attribute", "")
    if attr == "userData" or "UserData" in params:
        return PatternResult(blocked=True, message="Modifying instance UserData is blocked — can inject arbitrary startup scripts.")
    if attr == "instanceType" or "InstanceType" in params:
        return PatternResult(warning="Verify ENA is enabled before changing instance family.")
    if attr == "groupSet" or "Groups" in params:
        return PatternResult(warning="Changing instance security groups.")
    return PatternResult()


def _check_modify_sg_rules(params: dict) -> PatternResult:
    """Block widening existing SG rules to 0.0.0.0/0."""
    for rule in params.get("SecurityGroupRules", []):
        if not isinstance(rule, dict):
            continue
        sg_rule = rule.get("SecurityGroupRule", {})
        cidr = sg_rule.get("CidrIpv4", "")
        cidr6 = sg_rule.get("CidrIpv6", "")
        if cidr != "0.0.0.0/0" and cidr6 != "::/0":
            continue
        if str(sg_rule.get("IpProtocol", "")) == "-1":
            return PatternResult(blocked=True, message="Modifying SG rule to allow all traffic from 0.0.0.0/0 is blocked.")
        fp, tp = sg_rule.get("FromPort"), sg_rule.get("ToPort")
        if fp is not None and tp is not None:
            try:
                exposed = _SENSITIVE_PORTS.intersection(range(int(fp), int(tp) + 1))
                if exposed:
                    return PatternResult(blocked=True, message=f"Modifying SG rule to open ports {sorted(exposed)} to 0.0.0.0/0 is blocked.")
            except (ValueError, TypeError):
                pass
    return PatternResult()


def _check_ec2_create_route(params: dict) -> PatternResult:
    """Warn on routes to 0.0.0.0/0 without an IGW or NAT."""
    if params.get("DestinationCidrBlock") == "0.0.0.0/0" and not params.get("GatewayId") and not params.get("NatGatewayId"):
        return PatternResult(warning="Route to 0.0.0.0/0 without an internet gateway or NAT gateway.")
    return PatternResult()


def _check_ssm_send_command(params: dict) -> PatternResult:
    """Block dangerous commands and large blast radius."""
    doc_name = params.get("DocumentName", "AWS-RunShellScript")
    if doc_name not in ("AWS-RunShellScript", "AWS-RunPowerShellScript"):
        return PatternResult(warning=f"Non-standard SSM document: {doc_name}.")

    commands = (params.get("Parameters") or {}).get("commands", [])
    for cmd in (commands if isinstance(commands, list) else []):
        if isinstance(cmd, str):
            from core.sanitizer import get_sanitizer
            safe, reason = get_sanitizer().is_safe_command(cmd)
            if not safe:
                return PatternResult(blocked=True, message=f"Blocked: {reason} — command: {cmd[:80]}")

    instance_ids = params.get("InstanceIds", [])
    if isinstance(instance_ids, list):
        if len(instance_ids) > 20:
            return PatternResult(blocked=True, message=f"Sending command to {len(instance_ids)} instances is blocked. Maximum is 20.")
        if len(instance_ids) > 5:
            return PatternResult(warning=f"Sending command to {len(instance_ids)} instances.")

    if params.get("Targets"):
        return PatternResult(warning="Tag-based targeting may affect an unbounded number of instances.")
    return PatternResult()


def _check_ssm_automation(params: dict) -> PatternResult:
    """Block destructive SSM Automation documents."""
    _BLOCKED_DOCS = {
        "AWS-TerminateEC2Instance", "AWS-DeleteImage", "AWS-DeleteSnapshot",
        "AWS-DeleteCloudFormation", "AWS-DeleteEBSVolumeSnapshots",
    }
    if params.get("DocumentName") in _BLOCKED_DOCS:
        return PatternResult(blocked=True, message=f"SSM Automation document '{params['DocumentName']}' is blocked.")
    if params.get("Targets"):
        return PatternResult(warning="Tag-based targeting may affect an unbounded number of resources.")
    return PatternResult()


def _check_iam_policy_attach(params: dict) -> PatternResult:
    """Allow AWS-managed policies only. Block nuclear policies."""
    policy_arn = params.get("PolicyArn", "")
    if not policy_arn.startswith("arn:aws:iam::aws:policy/"):
        return PatternResult(blocked=True, message="Only AWS-managed policies can be attached via Liberra.")
    if policy_arn in _BLOCKED_IAM_MANAGED_POLICIES:
        return PatternResult(blocked=True, message=f"'{policy_arn.split('/')[-1]}' cannot be attached — grants excessive permissions.")
    return PatternResult()


def _check_iam_policy_detach(params: dict) -> PatternResult:
    if not params.get("PolicyArn"):
        return PatternResult(blocked=True, message="PolicyArn is required.")
    return PatternResult()


_PATTERN_CHECKERS = {
    "ec2:authorize_security_group_ingress": _check_sg_ingress,
    "ec2:authorize_security_group_egress":  _check_sg_egress,
    "ec2:run_instances":                    _check_ec2_run_instances,
    "ec2:create_route":                     _check_ec2_create_route,
    "ec2:modify_instance_attribute":        _check_modify_instance_attribute,
    "ec2:modify_security_group_rules":      _check_modify_sg_rules,
    "s3:put_bucket_policy":                 _check_s3_bucket_policy,
    "s3:put_bucket_acl":                    _check_s3_bucket_acl,
    "s3:put_public_access_block":           _check_s3_public_access_block,
    "rds:delete_db_instance":               _check_rds_delete,
    "rds:create_db_instance":               _check_rds_create,
    "ssm:send_command":                     _check_ssm_send_command,
    "ssm:start_automation_execution":       _check_ssm_automation,
    "iam:attach_role_policy":               _check_iam_policy_attach,
    "iam:detach_role_policy":               _check_iam_policy_detach,
}


# =============================================================================
# Full safety check — called for every operation
# =============================================================================

def full_safety_check(
    service: str,
    operation: str,
    parameters: Optional[dict] = None,
) -> Tuple[OperationSafety, PatternResult]:
    safety = classify_operation(service, operation, parameters)
    pattern = check_dangerous_patterns(service, operation, parameters)
    return safety, pattern