# Liberra Security Policy

Liberra connects to your AWS account via a cross-account IAM role. This repo shows exactly what that role can do, what is blocked at the IAM level, what is blocked in code, and how to verify everything yourself.

**Last synced with production: 2026-09-07, commit `9081d30`.** The `aws_safety.py` here is a byte-for-byte copy of that commit's file, and `iam-policy.json` is the policy that commit's generator produces. The commit is named so you can check rather than trust: if a claim here and the product ever disagree, the product wins and this file is the one that is wrong.

---

## How it connects

You deploy a CloudFormation stack that creates an IAM role in your AWS account. Liberra assumes that role via STS when acting on your behalf. Your credentials never leave your account.

Two protections are built into every connection:

- **External ID** — the role's trust policy requires a unique ID tied to your Liberra account. Nothing can assume the role without it.
- **1-hour sessions** — STS tokens expire after 60 minutes and rotate automatically. No long-lived credentials stored anywhere.

To revoke: delete the `liberra-standard-*` CloudFormation stack. Access is gone immediately.

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
| IAM changes | Blocked | Blocked, except attach/detach of AWS-managed policies — approval required, admin-level policies always denied |

Free tier is read-only. All write operations are blocked at the application layer before they reach AWS. Pro tier unlocks writes: every change starts with your approval — one yes covers the follow-through steps of that same request, and destructive or security-sensitive operations re-prompt every time.

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

## What Liberra can see

The role uses `Allow *`, so Liberra **can** read broadly across your account — that's what makes "ask anything about your cloud" work. You should know exactly what that means:

- It can read resource configurations, costs, logs, and metadata — anything the role permits.
- It **cannot** read Secrets Manager values — `get_secret_value` is a blocked read in code. Liberra can see that a secret exists, never its value.
- SSM Parameter Store values, including SecureString, **are** readable — you consent to this when you connect.
- Your questions and cloud metadata are sent to Anthropic's Claude API to generate answers. Anthropic does not train on this data. Your AWS credentials are never sent to the AI.
- Liberra stores: your Role ARN, an encrypted External ID, the Cloud Index, and chat history. Liberra never stores: access keys, session tokens, secret values.

---

## What the code blocks on top of IAM

Every request passes through an application safety layer before reaching AWS. See [`aws_safety.py`](./aws_safety.py) for the full logic and [`blocked-operations.md`](./blocked-operations.md) for the plain-English version.

In the order the code checks them:

1. **Six services blocked entirely** — `organizations`, `sts`, `account`, `sso`, `sso-admin`, `identitystore`. One deliberate exception: `sts.get_caller_identity`, a harmless "which account am I?" read. Everything else on these services is denied.
2. **Every delete, terminate, and purge — blocked by keyword.** Any operation whose name contains `delete`, `terminate`, or `purge` is refused before it reaches AWS. A keyword check, not a list — it covers every AWS service, including ones that don't exist yet.
3. **Targeted blocks** — operations that create long-lived credentials, plant persistence, or blind your audit trail (EventBridge rules, SSM activations, `kms.schedule_key_deletion`, `cloudtrail.stop_logging`, GuardDuty disassociation, IAM user/key creation). These never reach the approval box.
4. **Secrets stay secret** — `secretsmanager.get_secret_value` is a blocked read. Liberra can see that a secret exists but can never retrieve its value.
5. **Dangerous parameter patterns** — blocked regardless of operation: opening sensitive ports (SSH, RDP, databases) to `0.0.0.0/0`, public S3 bucket policies and ACLs, launching more than 20 instances in one call, injecting instance UserData, destructive shell commands via SSM, attaching admin-level IAM policies.
6. **Unknown operations fail safe** — anything unrecognized is treated as a write and pauses for approval. Nothing auto-executes by default.

---

## Verify it yourself

The policy is in this repo: [`iam-policy.json`](./iam-policy.json)

That file is the policy produced by the same generator that builds every user's CloudFormation
template, taken from commit `9081d30` — the commit currently deployed.

It is a **copy**, refreshed by hand, not a live mirror. It was two months stale once; naming the
commit is what makes that visible instead of invisible. If you want certainty rather than our word,
don't read this file at all — read the role in your own account:

```bash
aws iam get-role-policy --role-name <your-liberra-role> --policy-name LiberraStandardPolicy
```

That is the only copy that can actually affect your infrastructure.

### What is deliberately NOT in this repo yet

A much broader IAM deny — an additional `DenyDestroy` statement covering **332 delete/terminate/purge
actions**, derived from AWS's own service definitions — is **built and verified but not shipped.**
We have run `iam:SimulateCustomPolicy` against it and AWS returns `explicitDeny` for every
destructive action tested.

It is not in `iam-policy.json` because **no customer role carries it yet**, and this repo documents
what is deployed, not what is coming. When it ships, this file and this section change together.

Today, deletes are stopped by Liberra's application layer (`aws_safety.py`, published here in full)
plus the 16-action IAM deny in [`iam-policy.json`](./iam-policy.json) — not by a blanket
IAM-level delete ban.

---

## Questions

Open an issue in this repo.
