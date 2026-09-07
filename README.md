# Liberra Security

What Liberra can and cannot do inside your cloud account, and how to check it without trusting us.

**Synced with production `9081d30`, 2026-09-07.** The `*_safety.py` files are byte-for-byte copies from that commit, and `aws/iam-policy.json` is what that commit generates. If this repo and the product ever disagree, the product wins and this repo is what is wrong.

---

## What is in here

| | |
|---|---|
| [`aws/`](./aws) | The permissions your role gets, the stack you deploy, and the code that refuses a call. |
| [`azure/`](./azure) | The code that refuses an ARM call. Azure allows no policy-level equivalent. |
| [`gcp/`](./gcp) | The code that refuses a Google Cloud call. |

---

## What you grant

| | AWS | Azure | Google Cloud |
|---|---|---|---|
| **How** | Cross-account IAM role | Lighthouse delegation | Service account impersonation |
| **What we get** | The role, and only with your External ID | Built-in Contributor, on one subscription | `roles/editor`, or `roles/viewer` for read-only |
| **Secret stored** | None. STS tokens, 60 minutes, in memory | None | None |
| **You revoke by** | Deleting the CloudFormation stack | Removing the delegation | Removing the IAM binding |

Revocation is instant and needs nothing from us. No ticket, no waiting.

On AWS every session is stamped `SourceIdentity: liberra-<your-email>`, so every call Liberra makes appears in **your** CloudTrail under a name you can trace.

---

## Who refuses a delete

The three clouds do not hand us the same rope.

- **AWS.** The role's own policy carries an explicit `Deny`. In IAM a deny beats every allow, including your administrator's. AWS refuses us, not our code.
- **Google Cloud.** IAM Deny Policies can do the same. Built, not shipped, see below.
- **Azure.** Not possible. Lighthouse grants built-in roles only, and Azure lets no third party create a deny assignment. Here the refusal is **ours**, in code. That is weaker, and we would rather say it than let you assume otherwise. Full reason in [`azure/`](./azure).

---

## What the code refuses

1. **Delete, terminate, purge.** AWS by operation name, Azure by the HTTP verb `DELETE`, Google Cloud by `DELETE` and its destructive colon-verbs. A keyword rule rather than a list, so it covers services that do not exist yet.
2. **Account-level services.** On AWS: `organizations`, `sts`, `account`, `sso`, `sso-admin`, `identitystore`. One exception, `sts.get_caller_identity`. Azure and Google Cloud block their own equivalents.
3. **Secret values.** `secretsmanager.get_secret_value` and Secret Manager `:access`. We can see that a secret exists, never what is in it.
4. **Backdoors and audit blinding.** IAM users and access keys, scheduled rules, SSM activations, key deletion scheduling, stopping CloudTrail, disassociating GuardDuty, stopping the config recorder.
5. **Dangerous parameters, whatever the operation.** SSH, RDP or database ports open to `0.0.0.0/0`, public S3 policies and ACLs, more than 20 instances at once, UserData injection, admin-level IAM policies.
6. **Anything unrecognised** is treated as a write and waits for your approval. Nothing auto-executes by default.

Everything else is an ordinary write: Liberra proposes it, you approve it, then it runs.

---

## Check it yourself

Do not trust this repo. Ask your own cloud.

```bash
aws iam get-role-policy \
  --role-name <your-liberra-role> \
  --policy-name LiberraStandardPolicy

aws iam simulate-principal-policy \
  --policy-source-arn <your-liberra-role-arn> \
  --action-names ec2:TerminateInstances s3:DeleteBucket
```

The second command is AWS itself answering `explicitDeny`. That is the only opinion here that is not ours.

To tie this repo to your own account, every role we generate is tagged with the policy version it was built from:

```bash
aws iam list-role-tags --role-name <your-liberra-role>
```

Compare `PolicyVersion` against [`aws/iam-policy.json`](./aws/iam-policy.json). If they match, the file you just read is the rule you are actually living under.

The Azure and Google Cloud equivalents are in their folders.

---

## What Liberra can see

The AWS role is `Allow *` with an explicit deny list, which is what makes "ask anything about your cloud" work.

- It reads resource configuration, cost, logs and metadata across your account.
- It **cannot** read Secrets Manager values.
- SSM Parameter Store values, SecureString included, **are** readable. You consent to that when you connect.
- Your questions and your cloud metadata go to Anthropic's Claude API. Your cloud credentials never do.
- We store your role ARN, an encrypted External ID, your Cloud Index and your chat history. Never access keys, session tokens or secret values.

---

## Not here yet, on purpose

Built and verified, deployed to nobody, so not published:

- **A 332-action `DenyDestroy` for AWS**, derived from AWS's own service definitions. `iam:SimulateCustomPolicy` returns `explicitDeny` for every destructive action tested. Live customers are still on the 16-action deny in [`aws/iam-policy.json`](./aws/iam-policy.json).
- **A Google Cloud IAM Deny Policy**, 60 permission groups across 20 services.

This repo documents what customers have, not what is coming.

---

## Found a problem?

Mail **founder@liberraai.com**. Our [disclosure policy](https://liberraai.com/disclosure) carries a safe harbour: we will not pursue anyone acting in good faith under it.
