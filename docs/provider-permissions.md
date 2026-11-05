# Provider permissions

ShipSure needs read-only permissions for live provider checks. Grant only the actions for the commands in use. The AWS adapter uses the standard boto3 credential chain and never stores credentials.

## AWS action matrix

| Command | AWS actions called | Scope |
|---|---|---|
| `shipsure aws ec2` | `ec2:DescribeInstances`, `ec2:DescribeInstanceStatus` | Explicit instance IDs, up to 50 |
| `shipsure aws ecs` | `ecs:DescribeServices` | Explicit cluster and up to 10 service names |
| `shipsure aws lambda` | `lambda:GetFunctionConfiguration`, `logs:FilterLogEvents` | One function and its `/aws/lambda/<name>` log group |
| `shipsure aws cloudwatch-logs` | `logs:FilterLogEvents` | One named log group and a bounded time window |
| `shipsure aws iam-role` | `iam:GetRole`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:GetRolePolicy` | One named role and its referenced policy documents |
| `shipsure aws cloudformation` | `cloudformation:DescribeStacks`, `cloudformation:DescribeStackEvents` | One named stack |

No `Create`, `Put`, `Update`, `Delete`, `Run`, `Invoke`, `AssumeRole`, or policy simulation action is called by these commands. CloudWatch retrieval explicitly sets `unmask=False` and caps the time window to 24 hours and the result count to 500.

Example policy statements (replace resource ARNs and add only the actions for the checks you actually use):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ec2:DescribeInstances", "ec2:DescribeInstanceStatus"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["ecs:DescribeServices"],
      "Resource": "arn:aws:ecs:REGION:ACCOUNT:service/CLUSTER/SERVICE"
    },
    {
      "Effect": "Allow",
      "Action": ["lambda:GetFunctionConfiguration"],
      "Resource": "arn:aws:lambda:REGION:ACCOUNT:function:FUNCTION_NAME"
    },
    {
      "Effect": "Allow",
      "Action": ["logs:FilterLogEvents"],
      "Resource": "arn:aws:logs:REGION:ACCOUNT:log-group:LOG_GROUP_NAME:*"
    }
  ]
}
```

Some AWS `Describe` APIs do not support resource-level permissions and require `Resource: "*"`; keep such statements limited to those read actions. IAM role inspection also requires access to the selected role's policy metadata and version documents. Validate the exact resource support for the account's AWS partition and policy before granting it. AWS permissions and service APIs can change; consult [the EC2 API reference](https://docs.aws.amazon.com/boto3/latest/reference/services/ec2/client/describe_instances.html), [CloudWatch Logs `filter_log_events`](https://docs.aws.amazon.com/boto3/latest/reference/services/logs/client/filter_log_events.html), and the current service authorization references.

## Vercel permissions

Set `VERCEL_TOKEN` outside source control. Use a token scoped to the necessary Vercel team and project with read access to deployment, project, and environment metadata. ShipSure does not call the decrypted environment values endpoint. Runtime logs require a separately authenticated Vercel CLI installation; ShipSure runs only bounded `vercel logs` reads and does not install or update that CLI.
