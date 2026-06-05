# Liberra Blocked Operations

These operations are blocked at the **application layer** — Liberra's backend refuses to call them regardless of what the IAM role permits. They never reach AWS.

This is in addition to the [IAM-level deny list](./iam-policy.json), which is enforced by AWS itself.

---

## Universal keyword block

The first check in `classify_operation()` is a keyword test: if the boto3 method name contains `delete`, `terminate`, or `purge`, the operation is immediately classified as `BLOCKED` — before any service-specific checks run.

```python
_DELETE_KEYWORDS = frozenset({"delete", "terminate", "purge"})

if any(kw in op_lower for kw in _DELETE_KEYWORDS):
    return OperationSafety(level=SafetyLevel.BLOCKED, ...)
```

This means:

- `eks.delete_cluster` → BLOCKED
- `elasticache.delete_replication_group` → BLOCKED
- `emr.terminate_job_flows` → BLOCKED
- `kinesis.delete_stream` → BLOCKED
- `redshift.delete_cluster` → BLOCKED
- `lightsail.delete_instance` → BLOCKED
- `sqs.purge_queue` → BLOCKED
- Any service AWS adds in the future → BLOCKED automatically

No enumeration required. No per-service list to maintain. The keyword check covers all of AWS, present and future.

---

## Services blocked entirely

These 6 services are never accessible through Liberra under any circumstances:

| Service | Reason |
|---------|--------|
| `organizations` | Can remove accounts from your AWS Organization |
| `sts` | Can assume arbitrary roles — privilege escalation |
| `account` | Can close your entire AWS account |
| `sso` | Can grant org-wide access |
| `sso-admin` | Can manage SSO permission sets |
| `identitystore` | Can modify identity federation |

---

## Additional blocked operations (security and backdoor prevention)

The operations below do not contain `delete`, `terminate`, or `purge` in their names but are blocked because they create backdoors, enable persistent automation, or destroy security visibility.

### Lambda

| Operation | Reason |
|-----------|--------|
| `invoke` | Arbitrary code execution — too dangerous for generic executor |
| `invoke_async` | Same risk as invoke |

### EventBridge

| Operation | Reason |
|-----------|--------|
| `put_rule` | Can create persistent scheduled automation — backdoor risk |
| `put_targets` | Can attach targets to rules (invoke Lambda, etc.) |

### SSM

| Operation | Reason |
|-----------|--------|
| `create_activation` | Registers external machines into your SSM fleet — identity backdoor |
| `create_association` | Creates a persistent scheduled command on your instances — persistence vector |
| `create_document` | Stores a reusable automation script — code injection vehicle |

### CloudTrail

| Operation | Reason |
|-----------|--------|
| `stop_logging` | Silences audit trail — first move in an account compromise |

### GuardDuty

| Operation | Reason |
|-----------|--------|
| `disassociate_members` | Disconnects member accounts from threat detection |
| `disassociate_from_master_account` | Removes account from threat detection (older API) |
| `disassociate_from_administrator_account` | Same — newer API |

### Config

| Operation | Reason |
|-----------|--------|
| `stop_configuration_recorder` | Pauses compliance tracking |

### IAM

All IAM write operations are blocked. The only exceptions are `attach_role_policy` and `detach_role_policy`, which are allowed with canvas confirmation — but only for AWS-managed policies, and never for policies that grant admin-level access (`AdministratorAccess`, `PowerUserAccess`, `IAMFullAccess`).

| Operation | Reason |
|-----------|--------|
| `create_access_key` | Long-lived credentials — theft risk |
| `create_login_profile` | Expands attack surface |
| `create_user` | New identity — out of scope |
| `add_user_to_group` | Privilege escalation vector |

---

## Per-service reference: what the keyword block catches

The operations below all contain `delete`, `terminate`, or `purge` in their name and are caught by the universal keyword block. Listed here so you can verify specific operations by name.

### EC2

| Operation | Reason |
|-----------|--------|
| `terminate_instances` | Permanent — no recovery |
| `delete_volume` | Permanent data loss |
| `delete_snapshot` | Permanent data loss |
| `delete_key_pair` | Locks you out of instances using this key |
| `delete_security_group` | Can break running infrastructure |
| `delete_vpc` | Destroys entire network environment |
| `delete_subnet` | Breaks all resources in that subnet |
| `delete_internet_gateway` | Cuts internet access to entire VPC |
| `delete_nat_gateway` | Cuts outbound internet for private subnets |
| `delete_route_table` | Breaks routing for associated subnets |
| `delete_route` | Breaks specific routing rules |
| `delete_network_interface` | Can disconnect running instances |

### S3

| Operation | Reason |
|-----------|--------|
| `delete_bucket` | Permanent — bucket and all contents gone |
| `delete_objects` | Bulk deletion — can wipe entire bucket |

### RDS

| Operation | Reason |
|-----------|--------|
| `delete_db_instance` | Permanent data loss |
| `delete_db_cluster` | Permanent data loss |
| `delete_db_subnet_group` | Breaks RDS networking |
| `delete_db_parameter_group` | Can break dependent instances |
| `delete_db_cluster_parameter_group` | Can break dependent clusters |
| `delete_option_group` | Can break dependent instances |

### Lambda

| Operation | Reason |
|-----------|--------|
| `delete_function` | Permanent |
| `delete_layer_version` | Permanent — may break functions using this layer |

### ECS / ECR

| Operation | Reason |
|-----------|--------|
| `delete_cluster` | Destroys all services and tasks |
| `delete_service` | Stops running service |
| `delete_repository` | Permanent — all images lost |

### Load Balancers

| Operation | Reason |
|-----------|--------|
| `delete_load_balancer` | Cuts traffic to all targets |
| `delete_listener` | Removes traffic routing |

### Auto Scaling

| Operation | Reason |
|-----------|--------|
| `delete_auto_scaling_group` | Terminates all instances in the group |
| `delete_launch_configuration` | Breaks scaling if still referenced |

### Route 53

| Operation | Reason |
|-----------|--------|
| `delete_hosted_zone` | Destroys all DNS records |

### CloudFormation

| Operation | Reason |
|-----------|--------|
| `delete_stack` | Destroys all resources in the stack |

### CloudFront

| Operation | Reason |
|-----------|--------|
| `delete_distribution` | Takes down CDN distribution |
| `delete_streaming_distribution` | Takes down streaming distribution |

### SNS / SQS

| Operation | Reason |
|-----------|--------|
| `delete_topic` | All subscriptions lost |
| `delete_queue` | All messages and configuration lost |
| `purge_queue` | Wipes all messages from queue |

### CloudWatch / Logs

| Operation | Reason |
|-----------|--------|
| `delete_alarms` | Removes monitoring alerts |
| `delete_log_group` | Permanent log data loss |
| `delete_log_stream` | Permanent log data loss |

### KMS

| Operation | Reason |
|-----------|--------|
| `schedule_key_deletion` | All data encrypted with this key becomes permanently unrecoverable |
| `delete_key` | Same — catastrophic and irreversible |

### DynamoDB

| Operation | Reason |
|-----------|--------|
| `delete_table` | Permanent data loss — no recovery without backup |

### Secrets Manager

| Operation | Reason |
|-----------|--------|
| `delete_secret` | Loses stored credentials permanently |

### CloudTrail

| Operation | Reason |
|-----------|--------|
| `delete_trail` | Destroys audit history permanently |

### GuardDuty

| Operation | Reason |
|-----------|--------|
| `delete_detector` | Removes threat detection entirely |

### Config

| Operation | Reason |
|-----------|--------|
| `delete_configuration_recorder` | Removes compliance tracking |
| `delete_delivery_channel` | Stops Config from recording to S3/SNS |

---

## Additionally blocked: dangerous parameter patterns

Beyond blocking specific operations, Liberra also blocks specific parameter combinations:

- Opening security group ports 22, 3389, 3306, 5432, 27017, 6379, 1433, 9200, 9300, 5439 to `0.0.0.0/0` — blocked
- Opening all ports/protocols to `0.0.0.0/0` — blocked
- Public S3 bucket policies (`Principal: *`) — blocked
- Public S3 bucket ACLs (`public-read`, `public-read-write`) — blocked
- Deleting RDS instances without a final snapshot — blocked
- Launching more than 20 EC2 instances in a single call — blocked
- Running SSM commands known to be destructive — blocked
- Attaching `AdministratorAccess`, `PowerUserAccess`, or `IAMFullAccess` policies — blocked