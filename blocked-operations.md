# Liberra Blocked Operations

Every operation Liberra's AI attempts is classified **before it reaches AWS** — as a read, a write, or blocked. Blocked means it never executes, no matter what the AI or the user asks for. Writes pause for your approval.

This document describes the checks in the order the code runs them. The full enforcement source is [`aws_safety.py`](./aws_safety.py) — published verbatim from our backend. This sits **on top of** the [IAM-level deny list](./iam-policy.json), which AWS itself enforces.

**Last synced with production: 2026-07-07**

---

## 1. Six services blocked entirely

These services control who has access to everything else — the nuclear tier of AWS. No operation on them executes through Liberra:

| Service | Why it's blocked |
|---------|------------------|
| `organizations` | Can remove accounts from your AWS Organization |
| `sts` | Can assume arbitrary roles — privilege escalation |
| `account` | Can close your entire AWS account |
| `sso` | Can grant org-wide access |
| `sso-admin` | Can manage SSO permission sets |
| `identitystore` | Can modify identity federation |

**One deliberate exception:** `sts.get_caller_identity` — a harmless read that answers "which account am I connected to?". It changes nothing and reveals nothing but the account ID and role in use. Everything else on these six services is denied, including `sts.assume_role`, `sts.get_session_token`, and `sts.get_federation_token`.

---

## 2. Every delete, terminate, and purge — blocked by keyword

Any operation whose name contains `delete`, `terminate`, or `purge` is refused before it reaches AWS.

This is a **keyword check in code, not a list**. It covers every operation on every AWS service — including services and operations that don't exist yet. There is no per-service table to fall out of date, and no way for a new AWS API to slip through.

Asked to delete something, Liberra will analyze what's safe to remove, what depends on it, and what it costs — then point you to the AWS console to pull the trigger yourself.

One naming quirk worth knowing: `kms.schedule_key_deletion` says "deletion", not "delete", so the keyword check alone wouldn't catch it. It is blocked by name explicitly (see below) — and denied a second time at the IAM level.

---

## 3. Targeted blocks — backdoors, credentials, and audit-blinding

Deletes are handled by the keyword block above. This list is for operations that are dangerous in a different way: they create long-lived credentials, plant persistence, or blind your audit trail. A human clicking "Approve" on a one-line summary shouldn't be able to wave these through, so they never reach the approval box at all:

| Operation | Why it's blocked |
|-----------|------------------|
| `events.put_rule` / `events.put_targets` | Scheduled automation — a persistence/backdoor vector |
| `ssm.create_activation` | Registers external machines as managed instances — hybrid backdoor |
| `kms.schedule_key_deletion` | All data encrypted with the key becomes permanently unrecoverable |
| `cloudtrail.stop_logging` | Silences your audit trail — an attacker's first move |
| `guardduty.disassociate_members` / `disassociate_from_master_account` / `disassociate_from_administrator_account` | Disconnects threat detection |
| `config.stop_configuration_recorder` | Pauses compliance/change tracking |
| `iam.create_access_key` | Long-lived credentials — theft risk |
| `iam.create_login_profile` | Creates console passwords — expands attack surface |
| `iam.create_user` | New identities are out of Liberra's scope |
| `iam.add_user_to_group` | Privilege escalation vector |

---

## 4. IAM: all writes blocked, two gated exceptions

Every IAM write operation is blocked, with exactly two exceptions that require your approval and pass parameter inspection:

- `iam.attach_role_policy` — allowed **only** for AWS-managed policies (`arn:aws:iam::aws:policy/*`). Custom policy ARNs are blocked. Six admin-level managed policies can never be attached: `AdministratorAccess`, `PowerUserAccess`, `IAMFullAccess`, `IAMAdminAccess`, `AWSOrganizationsFullAccess`, `AWSAccountManagementFullAccess`.
- `iam.detach_role_policy` — detaching reduces access, so the application gate allows it with your approval. Note, however, that the [IAM-level deny list](./iam-policy.json) denies `iam:DetachRolePolicy` — so AWS itself refuses the call even after approval. In practice, detach does not execute; the deny direction wins.

IAM reads (list, get, describe) are free, like all reads.

---

## 5. Secrets stay secret

- `secretsmanager.get_secret_value` and `secretsmanager.get_random_password` are **blocked reads** — Liberra can see that a secret exists, but cannot retrieve its value. This also means secret values can never end up in an AI conversation.
- **Honest disclosure:** SSM Parameter Store reads — including `SecureString` parameters — are treated as normal reads. You consent to this when you connect your account; it's what makes parameter discovery work. When *writing* a `SecureString` parameter, the value is masked in the approval message.

---

## 6. Dangerous parameter patterns

Some operations are safe or dangerous depending on their parameters. These are inspected individually. **Blocked** means denied outright; **warned** means allowed, with the risk stated in the approval message.

**Blocked:**

| Pattern | Detail |
|---------|--------|
| Opening sensitive ports to the world | Ports 22 (SSH), 3389 (RDP), 3306, 5432, 27017, 6379, 1433, 9200/9300, 5439 (databases & search) to `0.0.0.0/0` or `::/0` — via new rules or rule modification |
| Opening all ports/protocols to the world | Any all-traffic ingress rule to `0.0.0.0/0` |
| Public S3 bucket policies | Any policy statement with `Principal: *` (all wildcard forms) |
| Public S3 bucket ACLs | `public-read`, `public-read-write`, `authenticated-read` |
| RDS deletion without a final snapshot | Defense-in-depth — deletes are already keyword-blocked |
| RDS reserved master usernames | `admin`, `root`, `postgres`, etc. — AWS rejects them anyway; blocked early with a clear message |
| Launching more than 20 EC2 instances in one call | Blast-radius cap |
| Modifying EC2 instance UserData | Can inject arbitrary startup scripts |
| Destructive shell commands via SSM | Each command is scanned; known-destructive commands are refused |
| SSM commands to more than 20 instances | Blast-radius cap |
| Destructive SSM Automation documents | `AWS-TerminateEC2Instance`, `AWS-DeleteImage`, `AWS-DeleteSnapshot`, `AWS-DeleteCloudFormation`, `AWS-DeleteEBSVolumeSnapshots` |

**Warned (allowed with your approval, risk stated):**

- Opening non-sensitive ports to the world
- All-traffic egress to `0.0.0.0/0`
- Disabling S3 public-access-block settings
- Creating a publicly accessible RDS instance
- Launching more than 10 instances (blocked above 20)
- Disabling termination protection or source/dest checks
- Changing instance security groups or instance types
- Large DynamoDB batch writes containing deletes
- Routes to `0.0.0.0/0` without an internet/NAT gateway
- SSM commands to more than 5 instances, tag-based targeting, or non-standard documents

---

## 7. What always re-asks

One approval covers the follow-through steps of the same request — that's what makes provisioning flow. But these operations re-prompt **every time**, even in the middle of an already-approved task:

- Opening ports / any security group rule change
- IAM policy attach/detach
- S3 exposure changes (bucket policy, ACL, public-access block)
- RDS instance modification (can flip public accessibility)
- EC2 instance attribute changes
- Running commands on servers (SSM)
- Write scripts (you see the actual code in the approval box)
- Anything classified as destructive

---

## 8. Unknown operations fail safe

If an operation's name doesn't match any known pattern, it is treated as a **write** — it pauses for your approval. Nothing unrecognized ever auto-executes.
