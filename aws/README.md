# AWS

| File | What it is |
|---|---|
| [`iam-policy.json`](./iam-policy.json) | The exact permissions your role gets. **Read this one first.** |
| [`cloudformation.yaml`](./cloudformation.yaml) | The stack you deploy. It creates that role and nothing else. |
| [`aws_safety.py`](./aws_safety.py) | The code that refuses a call before it reaches AWS. |

You grant a cross-account IAM role, usable only with your External ID, through STS
sessions that expire after 60 minutes. Revoke by deleting the stack.

Do not trust these files. Read the role in your own account:

```bash
aws iam get-role-policy \
  --role-name <your-liberra-role> \
  --policy-name LiberraStandardPolicy
```
