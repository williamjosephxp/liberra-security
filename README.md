# Liberra Security Policy

Liberra connects to your AWS account via a cross-account IAM role. This repository documents exactly what that role can access, what the application additionally blocks, and how you can verify everything yourself.

No "we take security seriously" copy. Just the specifics.

---

## How the connection works

**Cross-account IAM role** — you deploy a CloudFormation stack that creates an IAM role in your AWS account. Liberra's backend assumes this role via STS when acting on your behalf. Your credentials never leave your account.

**External ID** — the role's trust policy requires a unique External ID generated specifically for your Liberra account. Even Liberra's own backend can't assume the role without it. This prevents [confused deputy attacks](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html).

**1-hour sessions** — STS tokens expire after 60 minutes and are automatically rotated. No long-lived credentials are stored anywhere.

**Revoke anytime** — delete the `liberra-standard-*` CloudFormation stack from your AWS account. Access is gone immediately. No action required on Liberra's side.

---

## The IAM policy

See [`iam-policy.json`](./iam-policy.json) for the exact policy attached to the role.

**Strategy: `Allow *` with an explicit `Deny` on 16 unrecoverable operations.**

This is the same pattern used by Datadog, Vanta, and other enterprise cloud tools. The reason for `Allow *` rather than a long allowlist: AWS adds new services constantly, and Liberra tools work across any service your account uses. A tight allowlist would require constant maintenance and would silently break when you use a service not on the list. A short deny list of truly dangerous operations is more auditable and more honest.

### IAM-level deny list (enforced by AWS, not just our code)

| Category | Blocked actions |
|----------|----------------|
| IAM identity | `iam:CreateUser`, `iam:DeleteUser`, `iam:CreateLoginProfile`, `iam:CreateAccessKey`, `iam:DeleteRole`, `iam:DetachRolePolicy` |
| KMS | `kms:ScheduleKeyDeletion`, `kms:DeleteAlias`, `kms:DeleteImportedKeyMaterial` |
| Secrets | `secretsmanager:DeleteSecret` |
| Audit trails | `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `config:StopConfigurationRecorder`, `config:DeleteConfigurationRecorder` |
| Security posture | `ec2:DisableEbsEncryptionByDefault`, `guardduty:DisassociateFromMasterAccount` |

These are blocked at the IAM level — even if Liberra's application had a bug or was compromised, AWS would reject these calls.

---

## What the application additionally blocks

Beyond the IAM policy, Liberra's application layer blocks a further set of operations before they ever reach AWS. These are checked in code on every request, regardless of what the IAM role permits.

See [`blocked-operations.md`](./blocked-operations.md) for the full list with explanations.

**Six services are blocked entirely — no operation, ever:**
`organizations`, `sts`, `account`, `sso`, `sso-admin`, `identitystore`

**Key additional blocked categories:**
- EC2: `terminate_instances`, VPC/subnet/IGW/SG deletion, network disconnect operations
- S3: `delete_bucket`, `delete_objects` (bulk)
- RDS: `delete_db_instance`, `delete_db_cluster`, all related schema objects
- Lambda: `delete_function`, `invoke` (arbitrary code execution)
- ECS/ECR: `delete_cluster`, `delete_service`, `delete_repository`
- Messaging: `delete_topic`, `delete_queue`
- Audit: `delete_trail`, `stop_logging`, `delete_detector`, `stop_configuration_recorder`
- All IAM write operations (except attaching AWS-managed policies to existing roles, with confirmation)

Additionally, specific parameter combinations are blocked regardless of operation — opening sensitive ports to `0.0.0.0/0`, public S3 bucket policies, deleting RDS without a final snapshot, and others. See [`blocked-operations.md`](./blocked-operations.md).

---

## What requires your approval

Every operation that changes state in your account requires explicit confirmation before Liberra executes it. The AI proposes the action, you see exactly what will happen, and you click Approve or reject it.

**Always confirmed:**
- Creating, modifying, starting, or stopping any resource
- Updating security group rules or bucket policies
- Tagging resources
- Writing to SSM Parameter Store
- Any Terraform plan (shown in full before apply)

**Never confirmed (reads are automatic):**
Describe, list, and get operations are free — no confirmation required. This is how the AI stays informed about your infrastructure. If you ask "how many EC2 instances do I have running?" Liberra reads your account to answer. You connected the account knowing it would do this.

---

## Verifying the live policy

The current IAM policy is always available at:

```
GET https://app.liberra.ai/api/settings/iam-policy
```

This endpoint returns the exact policy JSON embedded in every user's CloudFormation template — generated from the same source code that builds the template, not a separate document.

---

## CloudFormation template

See [`cloudformation.yaml`](./cloudformation.yaml) for the structure of the stack users deploy. The actual template generated for each user has their unique External ID and Liberra's account ID pre-filled — the structure and permissions are identical to this example.

---

## Questions

If something here doesn't look right or you have questions about the security model, open an issue in this repo.
