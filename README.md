# Liberra Security

What Liberra can and cannot do inside your cloud account, and how to check it without taking our word for anything.

**Synced with production `9081d30`, 2026-09-07.** The three `*_safety.py` files here are byte-for-byte copies from that commit, and `aws/iam-policy.json` is what that commit's generator produces. The commit is named so you can check rather than trust. If this repo and the product ever disagree, the product wins and this repo is what is wrong.

---

## What you grant

| | AWS | Azure | Google Cloud |
|---|---|---|---|
| **How** | Cross-account IAM role | Lighthouse delegation | Service account impersonation |
| **What we get** | The role, and only with your External ID | Built-in Contributor, on one subscription | `roles/editor`, or `roles/viewer` for read-only |
| **Secret stored** | None. STS tokens, 60 minutes, in memory | None | None |
| **You revoke by** | Deleting the CloudFormation stack | Removing the delegation | Removing the IAM binding |

Revocation is instant and needs nothing from us. No ticket, no waiting.

On AWS every session is also stamped with `SourceIdentity: liberra-<your-email>`, so every call Liberra makes shows up in **your** CloudTrail under a name you can trace.

---

## Who refuses a delete

This is the part worth understanding, because the three clouds do not hand us the same rope.

- **AWS.** The role's own policy carries an explicit `Deny`. In IAM a deny beats every allow, including your administrator's. AWS refuses us, not our code.
- **Google Cloud.** IAM Deny Policies can do the same thing. See "Not here yet" below.
- **Azure.** Neither is possible. Lighthouse grants built-in roles only, Azure will not let a third party create a deny assignment, and Azure Policy has no caller condition, so a rule aimed at us would block your own deletes too. On Azure the refusal is **ours**, in code. That is a weaker guarantee, and we would rather say it than let you assume otherwise.

---

## What the code blocks, on every cloud

Published in full: [`aws/aws_safety.py`](./aws/aws_safety.py), [`azure/azure_safety.py`](./azure/azure_safety.py), [`gcp/gcp_safety.py`](./gcp/gcp_safety.py).

1. **Delete, terminate and purge are refused.** AWS matches the operation name, Azure matches the HTTP verb `DELETE`, Google Cloud matches both `DELETE` and its destructive colon-verbs. A keyword rule rather than a list, so it covers services that do not exist yet.
2. **Account-level services are blocked outright.** On AWS: `organizations`, `sts`, `account`, `sso`, `sso-admin`, `identitystore`. One exception, `sts.get_caller_identity`, a harmless "which account am I?" read. Azure and Google Cloud carry the same block over their own account-level namespaces and their org or folder operations.
3. **Secret values cannot be read.** `secretsmanager.get_secret_value` on AWS, Secret Manager `:access` on Google Cloud. Liberra can see that a secret exists, never what is in it.
4. **Backdoor and audit-blinding operations are blocked.** Creating IAM users or access keys, planting scheduled rules or SSM activations, scheduling key deletion, stopping CloudTrail, disassociating GuardDuty, stopping the config recorder. These never reach the approval box.
5. **Dangerous parameters are refused whatever the operation.** Opening SSH, RDP or database ports to `0.0.0.0/0`, public S3 bucket policies and ACLs, launching more than 20 instances at once, injecting UserData, attaching admin-level IAM policies.
6. **Anything unrecognised is treated as a write** and waits for your approval. Nothing auto-executes by default.

Everything not on that list is an ordinary write: Liberra proposes it, you approve it, then it runs.

---

## Check it yourself

Do not trust this repo. Ask your own cloud.

**AWS. Read the rule, then make AWS apply it.**

```bash
aws iam get-role-policy \
  --role-name <your-liberra-role> \
  --policy-name LiberraStandardPolicy

aws iam simulate-principal-policy \
  --policy-source-arn <your-liberra-role-arn> \
  --action-names ec2:TerminateInstances s3:DeleteBucket
```

The second command is AWS itself answering `explicitDeny`. That is the only opinion here that is not ours.

**AWS. Match your own role to this repo.** Every role we generate is tagged with the policy version it was built from.

```bash
aws iam list-role-tags --role-name <your-liberra-role>
```

Compare `PolicyVersion` against [`aws/iam-policy.json`](./aws/iam-policy.json). If they match, the file you just read is the rule you are actually living under.

**Azure. See exactly what you delegated.**

```bash
az managedservices assignment list
```

**Google Cloud. See exactly what you granted.**

```bash
gcloud projects get-iam-policy <project-id>
```

---

## Not here yet, on purpose

Two things are built and verified but **deployed to nobody**, so they are not in this repo:

- **A 332-action `DenyDestroy` for AWS**, derived from AWS's own service definitions. `iam:SimulateCustomPolicy` returns `explicitDeny` for every destructive action tested. Every live customer is still on the 16-action deny in [`aws/iam-policy.json`](./aws/iam-policy.json).
- **A Google Cloud IAM Deny Policy** covering 60 permission groups across 20 services, offered as an optional second step at connect.

This repo documents what customers actually have, not what is coming. When those ship, this repo changes with them.

---

## What Liberra can see

The AWS role uses `Allow *` with an explicit deny list, which is what makes "ask anything about your cloud" work. You should know exactly what that means:

- It can read resource configuration, cost, logs and metadata across your account.
- It **cannot** read Secrets Manager values. It can see that a secret exists, never its contents.
- SSM Parameter Store values, including SecureString, **are** readable. You consent to that when you connect.
- Your questions and your cloud metadata go to Anthropic's Claude API. Your cloud credentials never do.
- We store your role ARN, an encrypted External ID, your Cloud Index and your chat history. We never store access keys, session tokens or secret values.

---

## Found a problem?

Mail **founder@liberraai.com**. Our [disclosure policy](https://liberraai.com/disclosure) carries a safe harbour for good faith research: we will not pursue anyone acting under it.
