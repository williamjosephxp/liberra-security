# Google Cloud

| File | What it is |
|---|---|
| [`gcp_safety.py`](./gcp_safety.py) | The code that refuses a call before it reaches Google Cloud. |

You grant `roles/editor`, or `roles/viewer` for read-only, to a service account we
impersonate. Revoke by removing the IAM binding. See exactly what you granted:

```bash
gcloud projects get-iam-policy <project-id>
```

An IAM Deny Policy that makes **Google** refuse our deletes is built and verified,
but deployed to nobody, so it is not published here yet.
