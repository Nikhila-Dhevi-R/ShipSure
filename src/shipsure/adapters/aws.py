"""Read-only, resource-scoped AWS diagnostics using boto3's credential chain."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from shipsure.engine import _diag, diagnose_log_text
from shipsure.models import Diagnosis, Evidence, ProviderReport
from shipsure.security import redact_secrets

ClientFactory = Callable[[str, str | None], Any]


class AwsReadOnlyAdapter:
    """Use AWS's standard credential chain and only read operations for named resources."""

    def __init__(
        self,
        *,
        profile_name: str | None = None,
        region_name: str | None = None,
        client_factory: ClientFactory | None = None,
    ) -> None:
        self.region_name = region_name
        self._clients: dict[str, Any] = {}
        self._client_factory = client_factory
        if client_factory is None:
            try:
                import boto3  # type: ignore[import-untyped]
                from botocore.config import Config  # type: ignore[import-untyped]
            except ImportError as exc:
                raise RuntimeError(
                    "AWS support requires the optional dependency: pip install 'shipsure[aws]'"
                ) from exc
            self._session = boto3.Session(profile_name=profile_name, region_name=region_name)
            self._client_config = Config(
                retries={"total_max_attempts": 3, "mode": "standard"},
                connect_timeout=4,
                read_timeout=15,
                user_agent_extra="ShipSure/0.1 read-only-diagnostics",
            )
        else:
            self._session = None
            self._client_config = None

    def _client(self, service: str) -> Any:
        if service not in self._clients:
            if self._client_factory:
                self._clients[service] = self._client_factory(service, self.region_name)
            else:
                self._clients[service] = self._session.client(
                    service, region_name=self.region_name, config=self._client_config
                )
        return self._clients[service]

    @staticmethod
    def _evidence(
        source: str,
        location: str,
        detail: str,
        *,
        kind: Literal["log", "configuration", "source", "provider", "command"] = "provider",
    ) -> Evidence:
        return Evidence(source=source, location=location, excerpt=redact_secrets(detail), kind=kind)

    @staticmethod
    def _report(
        target: str,
        observations: list[Evidence],
        diagnoses: list[Diagnosis],
        limitations: list[str] | None = None,
    ) -> ProviderReport:
        unique = {item.id: item for item in diagnoses}
        ordered = sorted(
            unique.values(), key=lambda item: (-item.confidence, item.category, item.id)
        )
        return ProviderReport(
            provider="aws",
            target=target,
            observations=observations,
            diagnoses=ordered,
            limitations=limitations or [],
        )

    def _api_error(
        self, service: str, target: str, operation: str, exc: Exception
    ) -> ProviderReport:
        try:
            code = exc.response["Error"]["Code"]  # type: ignore[attr-defined]
            message = exc.response["Error"].get("Message", "")  # type: ignore[attr-defined]
        except (AttributeError, KeyError, TypeError):
            code = type(exc).__name__
            message = ""
        detail = redact_secrets(f"{code}: {message}")
        evidence = [self._evidence(f"AWS {service} API", f"{target}/{operation}", detail)]
        diagnoses = diagnose_log_text(detail, platform="AWS")
        if (
            code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}
            and not diagnoses
        ):
            diagnoses.append(
                _diag(
                    "permissions",
                    f"AWS read permission denied for {operation}",
                    f"The active AWS identity was not authorized to perform {operation}; ShipSure did not request a broader account-wide listing.",
                    0.9,
                    evidence,
                    f"Grant the minimum read permission for {service}:{operation} on the requested resource, then retry.",
                    [
                        "Confirm the AWS profile, region, and requested resource identifier.",
                        "Ask an administrator for the specific read permission only.",
                        "Retry this scoped diagnostic.",
                    ],
                )
            )
        return self._report(
            target,
            evidence,
            diagnoses,
            [f"AWS {service} {operation} failed ({code}); no further resources were queried."],
        )

    def inspect_ec2(self, instance_ids: list[str]) -> ProviderReport:
        if (
            not instance_ids
            or len(instance_ids) > 50
            or len(set(instance_ids)) != len(instance_ids)
        ):
            raise ValueError("provide 1 to 50 distinct EC2 instance IDs")
        if any(not re.fullmatch(r"i-[0-9a-fA-F]{8,17}", item) for item in instance_ids):
            raise ValueError("EC2 instance IDs must use the i- identifier format")
        target = "ec2:" + ",".join(instance_ids)
        client = self._client("ec2")
        try:
            response = client.describe_instances(InstanceIds=instance_ids)
            status_response = client.describe_instance_status(
                InstanceIds=instance_ids, IncludeAllInstances=True
            )
        except Exception as exc:
            if exc.__class__.__name__ == "ClientError":
                return self._api_error("ec2", target, "DescribeInstances", exc)
            raise
        observations: list[Evidence] = []
        diagnoses: list[Diagnosis] = []
        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instance_id = instance.get("InstanceId", "unknown")
                state = instance.get("State", {}).get("Name", "unknown")
                observations.append(
                    self._evidence(
                        "AWS EC2 DescribeInstances",
                        f"instance:{instance_id}/state",
                        f"state={state}",
                    )
                )
        for item in status_response.get("InstanceStatuses", []):
            instance_id = item.get("InstanceId", "unknown")
            instance_status = item.get("InstanceStatus", {}).get("Status", "not-reported")
            system_status = item.get("SystemStatus", {}).get("Status", "not-reported")
            evidence = [
                self._evidence(
                    "AWS EC2 DescribeInstanceStatus",
                    f"instance:{instance_id}/status",
                    f"instance={instance_status}; system={system_status}",
                )
            ]
            observations.extend(evidence)
            failed_checks = [
                name
                for name, value in (("instance", instance_status), ("system", system_status))
                if value not in {"ok", "not-reported"}
            ]
            if failed_checks:
                diagnoses.append(
                    _diag(
                        "infrastructure",
                        "EC2 status check is not healthy",
                        f"AWS reports {', '.join(failed_checks)} status as {instance_status if failed_checks == ['instance'] else system_status}; this check alone does not identify the operating-system root cause.",
                        0.9,
                        evidence,
                        "Use the matching instance or system status details to identify the failure before selecting a recovery action.",
                        [
                            "Review the EC2 status check details and recent system log output.",
                            "For an instance check, inspect guest OS/network health. For a system check, check AWS service events.",
                            "Recheck both status values after any approved recovery action.",
                        ],
                        ["A transient status check may recover without intervention."],
                    )
                )
        return self._report(
            target,
            observations,
            diagnoses,
            ["EC2 checks are read-only and scoped to explicitly supplied instance IDs."],
        )

    def inspect_ecs(self, cluster: str, service_names: list[str]) -> ProviderReport:
        if not cluster or not service_names or len(service_names) > 10:
            raise ValueError("provide a cluster and 1 to 10 ECS service names")
        client = self._client("ecs")
        target = f"ecs:{cluster}/" + ",".join(service_names)
        try:
            response = client.describe_services(cluster=cluster, services=service_names)
        except Exception as exc:
            if exc.__class__.__name__ == "ClientError":
                return self._api_error("ecs", target, "DescribeServices", exc)
            raise
        observations: list[Evidence] = []
        diagnoses: list[Diagnosis] = []
        for service in response.get("services", []):
            name = service.get("serviceName", "unknown")
            running = int(service.get("runningCount", 0))
            desired = int(service.get("desiredCount", 0))
            deployments = service.get("deployments", [])
            latest_deployments = [
                f"{item.get('status')}:{item.get('rolloutState', 'unknown')}"
                for item in deployments[:10]
            ]
            observations.append(
                self._evidence(
                    "AWS ECS DescribeServices",
                    f"service:{name}/counts",
                    f"running={running}; desired={desired}; deployments={', '.join(latest_deployments)}",
                )
            )
            for event in service.get("events", [])[:20]:
                message = str(event.get("message", ""))
                if not message:
                    continue
                evidence = [
                    self._evidence(
                        "AWS ECS service event",
                        f"service:{name}/event:{event.get('id', 'recent')}",
                        message,
                    )
                ]
                observations.extend(evidence)
                diagnoses.extend(diagnose_log_text(message, platform="AWS"))
            failed = [item for item in deployments if item.get("rolloutState") == "FAILED"]
            if failed:
                detail = "; ".join(
                    str(item.get("rolloutStateReason", "deployment rollout failed"))
                    for item in failed[:3]
                )
                evidence = [
                    self._evidence("AWS ECS DescribeServices", f"service:{name}/deployment", detail)
                ]
                diagnoses.append(
                    _diag(
                        "deployment",
                        "ECS service deployment failed",
                        f"ECS marked the rollout for {name} as failed: {detail}.",
                        0.97,
                        evidence,
                        "Inspect the stopped task reason, image reference, task execution role, and container logs before changing the service.",
                        [
                            "Read the failed deployment's task stop reason and essential container exit code.",
                            "Check image availability and the task execution role's pull permissions.",
                            "Deploy a corrected task definition only after reviewing the proposed change.",
                        ],
                    )
                )
            if desired > 0 and running < desired and not failed:
                evidence = [observations[-1]]
                diagnoses.append(
                    _diag(
                        "capacity",
                        "ECS service has fewer running tasks than desired",
                        f"The latest read shows {running} running task(s) against {desired} desired; this may be a rollout in progress or a placement/startup issue.",
                        0.61,
                        evidence,
                        "Inspect recent service events and stopped task reasons before changing desired count or capacity.",
                        [
                            "Check current deployment rollout state and recent ECS service events.",
                            "Inspect stopped task reasons, placement constraints, and available capacity.",
                            "Recheck running count after the service has had time to stabilize.",
                        ],
                        ["The service may be scaling or rolling out normally."],
                    )
                )
        for failure in response.get("failures", [])[:10]:
            observations.append(
                self._evidence(
                    "AWS ECS DescribeServices", f"cluster:{cluster}/failure", str(failure)
                )
            )
        return self._report(
            target,
            observations,
            diagnoses,
            ["ECS checks read only the explicitly supplied cluster and service names."],
        )

    def inspect_lambda(
        self, function_name: str, *, lookback_minutes: int = 60, log_limit: int = 100
    ) -> ProviderReport:
        if not function_name or not 1 <= lookback_minutes <= 24 * 60 or not 1 <= log_limit <= 500:
            raise ValueError(
                "provide a Lambda function name, lookback of 1-1440 minutes, and log limit of 1-500"
            )
        target = f"lambda:{function_name}"
        client = self._client("lambda")
        try:
            configuration = client.get_function_configuration(FunctionName=function_name)
        except Exception as exc:
            if exc.__class__.__name__ == "ClientError":
                return self._api_error("lambda", target, "GetFunctionConfiguration", exc)
            raise
        safe_fields = (
            "Runtime",
            "Handler",
            "Timeout",
            "MemorySize",
            "State",
            "StateReason",
            "LastUpdateStatus",
            "LastUpdateStatusReason",
            "PackageType",
            "Architectures",
            "EphemeralStorage",
        )
        observations = [
            self._evidence(
                "AWS Lambda GetFunctionConfiguration",
                f"{target}/{key}",
                f"{key}={configuration[key]}",
            )
            for key in safe_fields
            if key in configuration
        ]
        diagnoses: list[Diagnosis] = []
        if (
            configuration.get("State") == "Failed"
            or configuration.get("LastUpdateStatus") == "Failed"
        ):
            reason = (
                configuration.get("StateReason")
                or configuration.get("LastUpdateStatusReason")
                or "AWS reports the function state/update as failed."
            )
            evidence = [
                self._evidence(
                    "AWS Lambda GetFunctionConfiguration", f"{target}/state", str(reason)
                )
            ]
            diagnoses.append(
                _diag(
                    "deployment",
                    "Lambda function configuration or update failed",
                    redact_secrets(str(reason)),
                    0.96,
                    evidence,
                    "Compare the failed update reason with the published runtime, handler, architecture, and artifact before retrying deployment.",
                    [
                        "Inspect the function's recent CloudWatch logs and update reason.",
                        "Validate the handler path and deployment package for the configured runtime.",
                        "Retry deployment only after the failing configuration or artifact is corrected.",
                    ],
                )
            )
        configured_name = configuration.get("FunctionName") or function_name.rsplit(":", 1)[-1]
        log_group = f"/aws/lambda/{configured_name}"
        start_time = int(
            (datetime.now(UTC) - timedelta(minutes=lookback_minutes)).timestamp() * 1000
        )
        end_time = int(datetime.now(UTC).timestamp() * 1000)
        logs = self._client("logs")
        try:
            paginator = logs.get_paginator("filter_log_events")
            page_iterator = paginator.paginate(
                logGroupName=log_group,
                startTime=start_time,
                endTime=end_time,
                unmask=False,
                PaginationConfig={"PageSize": min(log_limit, 100), "MaxItems": log_limit},
            )
            messages = []
            for page in page_iterator:
                for event in page.get("events", []):
                    message = redact_secrets(str(event.get("message", "")), max_length=2000)
                    if message:
                        messages.append(message)
                        observations.append(
                            self._evidence(
                                "AWS CloudWatch FilterLogEvents",
                                f"{log_group}/event:{event.get('eventId', 'recent')}",
                                message,
                                kind="log",
                            )
                        )
        except Exception as exc:
            if exc.__class__.__name__ == "ClientError":
                return self._report(
                    target,
                    observations,
                    diagnoses,
                    [
                        f"Unable to read the named CloudWatch log group ({type(exc).__name__}); no logs were unmasked."
                    ],
                )
            raise
        diagnoses.extend(diagnose_log_text("\n".join(messages), platform="AWS"))
        return self._report(
            target,
            observations,
            diagnoses,
            [
                "Lambda configuration reads exclude function code, environment variable values, and secret configuration.",
                "CloudWatch event retrieval is bounded by a time window and result cap; unmask is explicitly disabled.",
            ],
        )

    def inspect_cloudwatch_logs(
        self,
        log_group_name: str,
        *,
        lookback_minutes: int = 60,
        log_limit: int = 100,
        filter_pattern: str | None = None,
    ) -> ProviderReport:
        """Read a named CloudWatch log group over a bounded window, with unmask disabled."""
        if (
            not log_group_name
            or len(log_group_name) > 512
            or not 1 <= lookback_minutes <= 24 * 60
            or not 1 <= log_limit <= 500
        ):
            raise ValueError(
                "provide an exact log group name, a 1-1440 minute lookback, and a 1-500 event limit"
            )
        if filter_pattern is not None and len(filter_pattern) > 256:
            raise ValueError("CloudWatch filter patterns are limited to 256 characters")
        target = f"cloudwatch-logs:{log_group_name}"
        client = self._client("logs")
        now = datetime.now(UTC)
        params: dict[str, Any] = {
            "logGroupName": log_group_name,
            "startTime": int((now - timedelta(minutes=lookback_minutes)).timestamp() * 1000),
            "endTime": int(now.timestamp() * 1000),
            "unmask": False,
            "PaginationConfig": {"PageSize": min(log_limit, 100), "MaxItems": log_limit},
        }
        if filter_pattern:
            params["filterPattern"] = filter_pattern
        try:
            pages = client.get_paginator("filter_log_events").paginate(**params)
            observations: list[Evidence] = []
            messages: list[str] = []
            for page in pages:
                for event in page.get("events", []):
                    message = redact_secrets(str(event.get("message", "")), max_length=2000)
                    if not message:
                        continue
                    messages.append(message)
                    observations.append(
                        self._evidence(
                            "AWS CloudWatch FilterLogEvents",
                            f"{log_group_name}/event:{event.get('eventId', 'recent')}",
                            message,
                            kind="log",
                        )
                    )
        except Exception as exc:
            if exc.__class__.__name__ == "ClientError":
                return self._api_error("logs", target, "FilterLogEvents", exc)
            raise
        diagnoses = diagnose_log_text("\n".join(messages), platform="AWS")
        return self._report(
            target,
            observations,
            diagnoses,
            [
                "CloudWatch log reads are limited to the named group, a 24-hour maximum window, a 500-event maximum, and unmask=False."
            ],
        )

    def inspect_iam_role(self, role_name: str, *, policy_limit: int = 20) -> ProviderReport:
        if not role_name or len(role_name) > 64 or not 1 <= policy_limit <= 20:
            raise ValueError("provide an IAM role name and a policy limit between 1 and 20")
        target = f"iam:role/{role_name}"
        client = self._client("iam")
        try:
            role_response = client.get_role(RoleName=role_name)
            attached = client.list_attached_role_policies(RoleName=role_name).get(
                "AttachedPolicies", []
            )
            inline_names = client.list_role_policies(RoleName=role_name).get("PolicyNames", [])
        except Exception as exc:
            if exc.__class__.__name__ == "ClientError":
                return self._api_error("iam", target, "GetRole/ListRolePolicies", exc)
            raise
        role = role_response.get("Role", {})
        assume = role.get("AssumeRolePolicyDocument", {})
        principals: set[str] = set()
        for statement in assume.get("Statement", []) if isinstance(assume, dict) else []:
            principal = statement.get("Principal", {})
            if isinstance(principal, dict):
                for value in principal.values():
                    principals.update(value if isinstance(value, list) else [value])
        observations = [
            self._evidence(
                "AWS IAM GetRole",
                f"{target}/trust-principals",
                ", ".join(sorted(principals))
                or "No service principal was parsed from the trust policy.",
            )
        ]
        diagnoses: list[Diagnosis] = []
        if len(attached) + len(inline_names) > policy_limit:
            attached = attached[:policy_limit]
            inline_names = inline_names[: max(0, policy_limit - len(attached))]
            observations.append(
                self._evidence(
                    "AWS IAM list APIs",
                    f"{target}/policies",
                    f"Policy inspection was capped at {policy_limit} entries.",
                )
            )

        policy_documents: list[tuple[str, Any]] = []
        for policy in attached:
            arn = policy.get("PolicyArn")
            if not arn:
                continue
            try:
                policy_meta = client.get_policy(PolicyArn=arn).get("Policy", {})
                version_id = policy_meta.get("DefaultVersionId")
                if not version_id:
                    continue
                document = (
                    client.get_policy_version(PolicyArn=arn, VersionId=version_id)
                    .get("PolicyVersion", {})
                    .get("Document", {})
                )
                policy_documents.append((str(policy.get("PolicyName", arn)), document))
                observations.append(
                    self._evidence(
                        "AWS IAM GetPolicyVersion",
                        f"{target}/managed-policy:{policy.get('PolicyName', arn)}",
                        f"defaultVersion={version_id}",
                    )
                )
            except Exception as exc:
                if exc.__class__.__name__ == "ClientError":
                    observations.append(
                        self._evidence(
                            "AWS IAM GetPolicyVersion",
                            f"{target}/managed-policy:{arn}",
                            f"Unable to read the default policy version ({type(exc).__name__}).",
                        )
                    )
                    continue
                raise
        for name in inline_names:
            try:
                document = client.get_role_policy(RoleName=role_name, PolicyName=name).get(
                    "PolicyDocument", {}
                )
                policy_documents.append((str(name), document))
                observations.append(
                    self._evidence(
                        "AWS IAM GetRolePolicy",
                        f"{target}/inline-policy:{name}",
                        "Inline policy document read for wildcard permission review.",
                    )
                )
            except Exception as exc:
                if exc.__class__.__name__ == "ClientError":
                    observations.append(
                        self._evidence(
                            "AWS IAM GetRolePolicy",
                            f"{target}/inline-policy:{name}",
                            f"Unable to read this policy ({type(exc).__name__}).",
                        )
                    )
                    continue
                raise

        broad_names = []
        for name, document in policy_documents:
            if not isinstance(document, dict):
                continue
            statements = document.get("Statement", [])
            statements = statements if isinstance(statements, list) else [statements]
            for statement in statements:
                if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
                    continue
                actions = statement.get("Action", [])
                resources = statement.get("Resource", [])
                actions = actions if isinstance(actions, list) else [actions]
                resources = resources if isinstance(resources, list) else [resources]
                if (
                    not statement.get("Condition")
                    and any(action == "*" for action in actions)
                    and any(resource == "*" for resource in resources)
                ):
                    broad_names.append(name)
        if broad_names:
            evidence = [
                self._evidence(
                    "AWS IAM policy documents",
                    f"{target}/wildcard-policies",
                    ", ".join(sorted(set(broad_names))),
                )
            ]
            diagnoses.append(
                _diag(
                    "permissions",
                    "IAM role contains an unconditioned all-action, all-resource Allow",
                    "At least one policy document grants Action '*' on Resource '*' without a Condition. This is a broad permission candidate and must be reviewed in the role's workload context.",
                    0.97,
                    evidence,
                    "Replace the broad statement with the exact actions and resource ARNs the workload needs, preserving required conditions and service trust relationships.",
                    [
                        "Confirm the role's workload and required API calls.",
                        "Draft a least-privilege policy and review it against the service authorization reference.",
                        "Test the replacement policy in a non-production environment before changing IAM.",
                    ],
                    [
                        "The wildcard statement may be constrained by a permissions boundary, SCP, or resource policy outside this role document."
                    ],
                )
            )
        return self._report(
            target,
            observations,
            diagnoses,
            [
                "IAM inspection was scoped to one named role and used only Get/List operations. Policy simulation and writes were not performed."
            ],
        )

    def inspect_cloudformation_stack(
        self, stack_name: str, *, event_limit: int = 100
    ) -> ProviderReport:
        if not stack_name or not 1 <= event_limit <= 500:
            raise ValueError("provide a stack name and an event limit between 1 and 500")
        target = f"cloudformation:stack/{stack_name}"
        client = self._client("cloudformation")
        try:
            stack_response = client.describe_stacks(StackName=stack_name)
            stack = (stack_response.get("Stacks") or [{}])[0]
            paginator = client.get_paginator("describe_stack_events")
            pages = paginator.paginate(
                StackName=stack_name, PaginationConfig={"PageSize": 100, "MaxItems": event_limit}
            )
        except Exception as exc:
            if exc.__class__.__name__ == "ClientError":
                return self._api_error(
                    "cloudformation", target, "DescribeStacks/DescribeStackEvents", exc
                )
            raise
        observations = [
            self._evidence(
                "AWS CloudFormation DescribeStacks",
                f"{target}/status",
                f"StackStatus={stack.get('StackStatus', 'unknown')}; LastUpdatedTime={stack.get('LastUpdatedTime', '')}",
            )
        ]
        diagnoses: list[Diagnosis] = []
        for page in pages:
            for event in page.get("StackEvents", []):
                status = str(event.get("ResourceStatus", ""))
                reason = str(event.get("ResourceStatusReason", ""))
                if not status.endswith("_FAILED"):
                    continue
                evidence = [
                    self._evidence(
                        "AWS CloudFormation DescribeStackEvents",
                        f"{target}/resource:{event.get('LogicalResourceId', 'unknown')}",
                        f"{status}: {reason}",
                    )
                ]
                observations.extend(evidence)
                diagnoses.append(
                    _diag(
                        "deployment",
                        "CloudFormation resource operation failed",
                        f"Resource {event.get('LogicalResourceId', 'unknown')} reached {status}: {redact_secrets(reason) or 'no failure reason was supplied'}.",
                        0.94,
                        evidence,
                        "Review the first failed resource event and its service-specific details before changing the template or retrying the stack operation.",
                        [
                            "Inspect earlier events for the first failure in the dependency chain.",
                            "Validate the affected resource configuration and permissions.",
                            "Review a change set before applying template changes.",
                        ],
                    )
                )
        return self._report(
            target,
            observations,
            diagnoses,
            [
                "CloudFormation inspection read stack status and a capped event history; no template execution or stack mutation was performed."
            ],
        )
