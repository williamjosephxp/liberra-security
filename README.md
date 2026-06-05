# Liberra Security Policy

Liberra connects to your AWS account via a cross-account IAM role. This repo shows exactly what that role can do, what is blocked at the IAM level, what is blocked in code, and how to verify everything yourself.

---

## How it connects

You deploy a CloudFormation stack that creates an IAM role in your AWS account. Liberra assumes that role via STS when acting on your behalf. Your credentials never leave your account.

Two protections are built into every connection:

- **External ID** — the role's trust policy requires a unique ID tied to your Liberra account. Nothing can assume the role without it.
- **1-hour sessions** — STS tokens expire after 60 minutes and rotate automatically. No long-lived credentials stored anywhere.

---

## You are always in control

Liberra does not control your AWS account. You do. The IAM role lives in your account, not ours. To revoke all access, delete the `liberra-standard-*` CloudFormation stack. Access is gone immediately. No support ticket, no waiting, nothing to clean up on our end.

---

## Free vs Pro

| | Free | Pro |
|---|---|---|
| Read your AWS account | Yes | Yes |
| View costs and usage | Yes | Yes |
| Make changes to resources | No | Yes, with your approval |
| Destructive operations | Never | Never |
| IAM changes | Never | Never |

Free tier is read-only. All write operations are blocked at the application layer before they reach AWS. Pro tier unlocks writes, but every action requires your explicit approval before anything executes.

---

## The IAM policy

See [`iam-policy.json`](./iam-policy.json) for the exact policy every user gets.

The policy uses `Allow *` with an explicit deny list. This lets Liberra work across any AWS service in your account without breaking when AWS adds new services. The deny list below is enforced by AWS itself, not by our code.

| Category | Blocked actions |
|---|---|
| IAM identity | CreateUser, DeleteUser, CreateLoginProfile, CreateAccessKey, DeleteRole, DetachRolePolicy |
| KMS | ScheduleKeyDeletion, DeleteAlias, DeleteImportedKeyMaterial |
| Secrets | DeleteSecret |
| Audit trails | StopLogging, DeleteTrail, StopConfigurationRecorder, DeleteConfigurationRecorder |
| Security posture | DisableEbsEncryptionByDefault, DisassociateFromMasterAccount |

---

## What the code blocks on top of IAM

Every request passes through an application safety layer before reaching AWS. See [`aws_safety.py`](./aws_safety.py) for the full logic.

Six services are blocked entirely, no operation ever: `organizations`, `sts`, `account`, `sso`, `sso-admin`, `identitystore`

**All delete, terminate, and purge operations are hard-blocked.** Any boto3 method with `delete`, `terminate`, or `purge` in its name is classified as `BLOCKED` before it reaches AWS — across every AWS service, with no exceptions. This is a keyword check in code, not a per-operation list. It covers EKS, ElastiCache, Kinesis, Glue, Redshift, Lightsail, and any service AWS adds in the future automatically.

Additional operations blocked for security reasons — these do not follow the delete/terminate/purge naming pattern but are blocked because they create backdoors or blind spots:

| Service | Blocked | Why |
|---|---|---|
| Lambda | `invoke`, `invoke_async` | Arbitrary code execution |
| EventBridge | `put_rule`, `put_targets` | Can create persistent scheduled automation |
| SSM | `create_activation`, `create_association`, `create_document` | Managed instance backdoor vectors |
| CloudTrail | `stop_logging` | Silences audit trail |
| GuardDuty | `disassociate_members`, `disassociate_from_master_account`, `disassociate_from_administrator_account` | Disconnects threat detection |
| Config | `stop_configuration_recorder` | Pauses compliance recording |
| IAM | all write operations | Identity changes out of scope |

Specific dangerous parameter combinations are also blocked regardless of operation: opening ports to `0.0.0.0/0`, public S3 bucket policies, RDS deletion without a final snapshot.

---

## Verify it yourself

The policy is in this repo: [`iam-policy.json`](./iam-policy.json)

That file is generated from the same source code that builds every user's CloudFormation template. What you see there is exactly what gets deployed to your AWS account.

---

## Questions

Open an issue in this repo.