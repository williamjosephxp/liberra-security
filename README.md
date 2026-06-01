# Liberra Security Policy

Liberra connects to your AWS account via a cross-account IAM role. This repo shows exactly what that role can do, what is blocked at the IAM level, what is blocked in code, and how to verify everything yourself.

---

## How it connects

You deploy a CloudFormation stack that creates an IAM role in your AWS account. Liberra assumes that role via STS when acting on your behalf. Your credentials never leave your account.

Two protections are built into every connection:

- **External ID** — the role's trust policy requires a unique ID tied to your Liberra account. Nothing can assume the role without it.
- **1-hour sessions** — STS tokens expire after 60 minutes and rotate automatically. No long-lived credentials stored anywhere.

To revoke: delete the `liberra-standard-*` CloudFormation stack. Access is gone immediately.

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

Key operations blocked in code:

| Service | Blocked |
|---|---|
| EC2 | terminate_instances, VPC/subnet/IGW/SG deletion, network disconnect operations |
| S3 | delete_bucket, bulk delete_objects |
| RDS | delete_db_instance, delete_db_cluster, all schema objects |
| Lambda | delete_function, invoke (arbitrary code execution) |
| ECS / ECR | delete_cluster, delete_service, delete_repository |
| IAM | all write operations |
| Messaging | delete_topic, delete_queue |
| Audit | delete_trail, stop_logging, delete_detector |

Specific dangerous parameter combinations are also blocked regardless of operation: opening ports to `0.0.0.0/0`, public S3 bucket policies, RDS deletion without a final snapshot.

---

## Verify it yourself

The live policy is always available at:

```
GET https://app.liberra.ai/api/settings/iam-policy
```

This returns the exact JSON embedded in every user's CloudFormation template, generated from the same source that builds it.

---

## Questions

Open an issue in this repo.
