from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from shipsure.mcp_server import build_server


class McpServerTests(unittest.TestCase):
    def test_tools_are_registered_with_read_only_annotations(self) -> None:
        server = build_server()
        tools = asyncio.run(server.list_tools())
        by_name = {tool.name: tool for tool in tools}

        self.assertGreaterEqual(len(tools), 18)
        self.assertTrue(
            {
                "diagnose_project",
                "analyze_deployment_logs",
                "suggest_safe_fix",
                "verify_proposed_fix",
                "inspect_vercel_deployment",
                "inspect_aws_ec2",
                "inspect_aws_lambda",
                "inspect_aws_iam_role",
            }.issubset(by_name)
        )
        self.assertTrue(all(tool.annotations.read_only_hint is True for tool in tools))

    def test_mcp_diagnosis_uses_shared_engine_and_does_not_modify_files(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            root = Path(temp_dir)
            (root / "package.json").write_text(
                '{"scripts":{"build":"vite build"},"devDependencies":{"vite":"^5"}}',
                encoding="utf-8",
            )
            server = build_server()
            result = asyncio.run(
                server.call_tool(
                    "diagnose_project",
                    {
                        "project_root": str(root),
                        "logs": "sh: vite: not found",
                        "platform": "vercel",
                    },
                )
            )
            content = "".join(block.text for block in result.content if hasattr(block, "text"))
            decoded = json.loads(content)
            self.assertTrue((root / "package.json").exists())

        self.assertEqual(decoded["status"], "issues_found")
        self.assertEqual(decoded["diagnoses"][0]["category"], "build")

    def test_fix_tool_only_returns_preview(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            root = Path(temp_dir)
            target = root / "Procfile"
            target.write_text("web: uvicorn main:app\n", encoding="utf-8")
            server = build_server()
            result = asyncio.run(
                server.call_tool(
                    "suggest_safe_fix",
                    {
                        "project_root": str(root),
                        "path": "Procfile",
                        "old_text": "main:app",
                        "new_text": "app.main:app",
                    },
                )
            )
            content = "".join(block.text for block in result.content if hasattr(block, "text"))
            decoded = json.loads(content)
            self.assertEqual(target.read_text(encoding="utf-8"), "web: uvicorn main:app\n")

        self.assertTrue(decoded["preview_only"])


if __name__ == "__main__":
    unittest.main()
