from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import patch

import httpx

from shipsure.adapters.aws import AwsReadOnlyAdapter
from shipsure.adapters.vercel import VercelApiError, VercelReadOnlyAdapter


class FakePaginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages
        self.calls: list[dict[str, Any]] = []

    def paginate(self, **kwargs: Any) -> list[dict[str, Any]]:
        self.calls.append(kwargs)
        return self.pages


class FakePipe:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def read(self, size: int) -> bytes:
        chunk, self.data = self.data[:size], self.data[size:]
        return chunk


class FakeProcess:
    def __init__(self, stdout: bytes, stderr: bytes = b"", returncode: int = 0) -> None:
        self.stdout = FakePipe(stdout)
        self.stderr = FakePipe(stderr)
        self.returncode = returncode

    def wait(self, timeout: int | None = None) -> int:
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9


class FakeAwsClient:
    def __init__(self, **responses: Any) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.paginators: dict[str, FakePaginator] = {}

    def __getattr__(self, name: str) -> Any:
        if name == "get_paginator":

            def get_paginator(operation: str) -> FakePaginator:
                self.calls.append(("get_paginator:" + operation, {}))
                paginator = FakePaginator(self.responses.get("pages_" + operation, []))
                self.paginators[operation] = paginator
                return paginator

            return get_paginator

        def call(**kwargs: Any) -> Any:
            self.calls.append((name, kwargs))
            response = self.responses.get(name, {})
            return response(**kwargs) if callable(response) else response

        return call


class VercelReadOnlyTests(unittest.TestCase):
    def test_capped_environment_metadata_does_not_support_absence(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/events"):
                return httpx.Response(
                    200, json=[{"text": "Environment Variable DATABASE_URL not found"}]
                )
            if request.url.path.endswith("/env"):
                return httpx.Response(
                    200,
                    json={
                        "env": [{"key": f"VAR_{i}"} for i in range(500)] + [{"key": "DATABASE_URL"}]
                    },
                )
            if request.url.path.startswith("/v9/projects/"):
                return httpx.Response(200, json={"id": "project_123"})
            return httpx.Response(200, json={"id": "dpl_example", "readyState": "READY"})

        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            adapter = VercelReadOnlyAdapter(token="test-token", client=client)
            report = adapter.inspect_deployment("dpl_example", project_id="project_123")

        finding = next(d for d in report.diagnoses if d.category == "configuration")
        self.assertTrue(any("capped" in item for item in report.limitations))
        self.assertFalse(
            any("No Vercel environment metadata" in item.excerpt for item in finding.evidence)
        )
        self.assertEqual(finding.confidence, 0.9)

    def test_reads_env_variable_names_without_returning_secret_values(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(
                200,
                json={
                    "env": [
                        {
                            "key": "DATABASE_URL",
                            "type": "encrypted",
                            "target": ["production"],
                            "value": "secret-database-value",
                        }
                    ]
                },
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        adapter = VercelReadOnlyAdapter(token="vercel_testtoken123456789", client=client)
        report = adapter.inspect_environment("project_123", team_id="team_456")

        self.assertEqual(
            report.observations[0].excerpt, "DATABASE_URL (encrypted; targets: production)"
        )
        self.assertNotIn("secret-database-value", str(report.model_dump()))
        self.assertEqual(requests[0].method, "GET")
        self.assertEqual(requests[0].headers["Authorization"], "Bearer vercel_testtoken123456789")
        self.assertIn("teamId=team_456", str(requests[0].url))
        client.close()

    def test_deployment_events_become_redacted_evidence_and_findings(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "/events" in request.url.path:
                return httpx.Response(
                    200,
                    json=[
                        {"type": "stderr", "text": "Task timed out after 10 seconds", "created": 1}
                    ],
                )
            return httpx.Response(
                200, json={"id": "dpl_example", "readyState": "ERROR", "errorCode": "BUILD_FAILED"}
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        adapter = VercelReadOnlyAdapter(token="vercel_testtoken123456789", client=client)
        report = adapter.inspect_deployment("dpl_example", project_id="project_123")

        self.assertTrue(any(d.category == "runtime" for d in report.diagnoses))
        self.assertTrue(any(d.category == "deployment" for d in report.diagnoses))
        self.assertTrue(any(e.kind == "log" for e in report.observations))
        self.assertTrue(any(e.kind == "provider" for e in report.observations))
        client.close()

    def test_refuses_oversized_provider_response(self) -> None:
        client = httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, content=b" " * 4_000_001)
            )
        )
        adapter = VercelReadOnlyAdapter(token="vercel_testtoken123456789", client=client)
        with self.assertRaisesRegex(VercelApiError, "response exceeds"):
            adapter.inspect_project("project_123")
        client.close()

    def test_runtime_log_command_is_bounded_non_streaming_and_read_only(self) -> None:
        output = b'{"level":"error","message":"FUNCTION_INVOCATION_FAILED"}\n'
        fake_process = FakeProcess(output)
        with (
            patch("shipsure.adapters.vercel.shutil.which", return_value="vercel.exe"),
            patch("shipsure.adapters.vercel.subprocess.Popen", return_value=fake_process) as popen,
        ):
            adapter = VercelReadOnlyAdapter()
            report = adapter.inspect_runtime_logs("dpl_example", limit=12, since="30m")
            adapter.close()

        command = popen.call_args.args[0]
        self.assertIn("--no-follow", command)
        self.assertNotIn("--follow", command)
        self.assertEqual(command[command.index("--limit") + 1], "12")
        self.assertFalse(popen.call_args.kwargs["shell"])
        self.assertTrue(any(d.category == "runtime" for d in report.diagnoses))

    def test_environment_name_metadata_is_correlated_with_missing_variable_log(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/events"):
                return httpx.Response(
                    200, json=[{"text": "Environment Variable DATABASE_URL not found"}]
                )
            if request.url.path.endswith("/env"):
                return httpx.Response(
                    200,
                    json={
                        "env": [
                            {
                                "key": "API_URL",
                                "type": "encrypted",
                                "target": ["production"],
                                "value": "sensitive-secret-value",
                            }
                        ]
                    },
                )
            if request.url.path.startswith("/v9/projects/"):
                return httpx.Response(200, json={"id": "project_123", "framework": "vite"})
            return httpx.Response(
                200, json={"id": "dpl_example", "readyState": "READY", "projectId": "project_123"}
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        adapter = VercelReadOnlyAdapter(token="vercel_testtoken123456789", client=client)
        report = adapter.inspect_deployment("dpl_example", project_id="project_123")

        config_finding = next(d for d in report.diagnoses if d.category == "configuration")
        self.assertTrue(
            any(
                "DATABASE_URL" in item.excerpt and "No Vercel environment metadata" in item.excerpt
                for item in config_finding.evidence
            )
        )
        self.assertNotIn("sensitive-secret-value", str(report.model_dump()))
        client.close()


class AwsReadOnlyTests(unittest.TestCase):
    def test_lambda_reads_config_and_recent_logs_without_unmasking(self) -> None:
        lambda_client = FakeAwsClient(
            get_function_configuration={
                "FunctionName": "api-handler",
                "Runtime": "python3.12",
                "Handler": "app.handler",
                "Timeout": 3,
                "MemorySize": 128,
                "State": "Active",
                "LastUpdateStatus": "Successful",
            }
        )
        logs_client = FakeAwsClient(
            pages_filter_log_events=[
                {"events": [{"timestamp": 1000, "message": "Task timed out after 3.00 seconds"}]}
            ]
        )
        calls: list[str] = []

        def factory(service: str, region: str | None) -> FakeAwsClient:
            calls.append(service)
            return {"lambda": lambda_client, "logs": logs_client}[service]

        adapter = AwsReadOnlyAdapter(region_name="us-east-1", client_factory=factory)
        report = adapter.inspect_lambda("api-handler", lookback_minutes=5)

        self.assertTrue(any(d.category == "runtime" for d in report.diagnoses))
        log_call = next(
            call for call in logs_client.calls if call[0] == "get_paginator:filter_log_events"
        )
        self.assertIn("logs", calls)
        self.assertEqual(log_call[0], "get_paginator:filter_log_events")
        paginator_args = logs_client.paginators["filter_log_events"].calls[0]
        self.assertFalse(paginator_args["unmask"])
        self.assertEqual(paginator_args["PaginationConfig"]["MaxItems"], 100)
        self.assertFalse(
            any(
                name.startswith(("update", "put", "delete", "create", "invoke"))
                for name, _ in lambda_client.calls + logs_client.calls
            )
        )

    def test_lambda_arn_uses_configured_function_name_for_log_group(self) -> None:
        lambda_client = FakeAwsClient(
            get_function_configuration={"FunctionName": "api-handler", "Runtime": "python3.12"}
        )
        logs_client = FakeAwsClient(pages_filter_log_events=[])
        adapter = AwsReadOnlyAdapter(
            client_factory=lambda service, region: {
                "lambda": lambda_client,
                "logs": logs_client,
            }[service]
        )

        adapter.inspect_lambda("arn:aws:lambda:us-east-1:123456789012:function:api-handler")

        request = logs_client.paginators["filter_log_events"].calls[0]
        self.assertEqual(request["logGroupName"], "/aws/lambda/api-handler")

    def test_ec2_status_check_failure_is_reported_from_read_only_calls(self) -> None:
        ec2 = FakeAwsClient(
            describe_instances={
                "Reservations": [
                    {"Instances": [{"InstanceId": "i-12345678", "State": {"Name": "running"}}]}
                ]
            },
            describe_instance_status={
                "InstanceStatuses": [
                    {
                        "InstanceId": "i-12345678",
                        "InstanceStatus": {"Status": "impaired"},
                        "SystemStatus": {"Status": "ok"},
                    }
                ]
            },
        )
        adapter = AwsReadOnlyAdapter(client_factory=lambda service, region: ec2)
        report = adapter.inspect_ec2(["i-12345678"])

        self.assertTrue(any(d.category == "infrastructure" for d in report.diagnoses))
        self.assertEqual(ec2.calls[0][0], "describe_instances")
        self.assertEqual(ec2.calls[1][0], "describe_instance_status")
        self.assertTrue(all(name.startswith(("describe", "get", "list")) for name, _ in ec2.calls))

    def test_iam_role_wildcard_grant_is_evidence_backed_and_only_read(self) -> None:
        iam = FakeAwsClient(
            get_role={
                "Role": {
                    "RoleName": "app-role",
                    "AssumeRolePolicyDocument": {
                        "Statement": [{"Principal": {"Service": "lambda.amazonaws.com"}}]
                    },
                }
            },
            list_attached_role_policies={
                "AttachedPolicies": [
                    {
                        "PolicyName": "wide-policy",
                        "PolicyArn": "arn:aws:iam::123456789012:policy/wide-policy",
                    }
                ]
            },
            list_role_policies={"PolicyNames": []},
            get_policy={"Policy": {"DefaultVersionId": "v3"}},
            get_policy_version={
                "PolicyVersion": {
                    "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
                }
            },
        )
        adapter = AwsReadOnlyAdapter(client_factory=lambda service, region: iam)
        report = adapter.inspect_iam_role("app-role")

        self.assertTrue(any(d.category == "permissions" for d in report.diagnoses))
        operations = [name for name, _ in iam.calls]
        self.assertTrue(all(name.startswith(("get", "list")) for name in operations))


if __name__ == "__main__":
    unittest.main()
