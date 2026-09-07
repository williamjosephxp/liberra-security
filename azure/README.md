# Azure

| File | What it is |
|---|---|
| [`azure_safety.py`](./azure_safety.py) | The code that refuses an ARM call before it reaches Azure. |

**There is no policy file here, and that is the honest answer rather than an
omission.** Lighthouse grants built-in roles only, Azure will not let a third party
create a deny assignment, and Azure Policy cannot condition on the caller, so a rule
aimed at us would block your own deletes too. On AWS and Google Cloud the cloud
refuses us. On Azure our code does, and the file above is that code.

You grant built-in Contributor on one subscription. Revoke by removing the
delegation. See exactly what you delegated:

```bash
az managedservices assignment list
```
