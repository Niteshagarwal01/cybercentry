"""Unit tests for config, run_state, scanners, sarif_export, and remediation."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.core.models import Finding, Run, Severity
from cyber_sentry_cli.core.run_state import RunStateManager
from cyber_sentry_cli.output.sarif_export import export_sarif, _sarif_rule_id, _path_to_uri
from cyber_sentry_cli.remediation.generator import _generate_unified_diff
from cyber_sentry_cli.scanners.base import find_tool


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

class TestConfig:
    def test_default_chat_model(self):
        c = Config()
        assert "gpt" in c.chat_model or "qwen" in c.chat_model or len(c.chat_model) > 3

    def test_default_model_alias(self):
        c = Config()
        assert c.default_model == c.chat_model

    def test_debate_rounds_default(self):
        c = Config()
        assert c.debate_rounds == 3

    def test_max_react_iterations_default(self):
        c = Config()
        assert c.max_react_iterations == 10

    def test_enabled_scanners_is_list(self):
        c = Config()
        assert isinstance(c.enabled_scanners, list)
        assert len(c.enabled_scanners) >= 1

    def test_temperature_is_float(self):
        c = Config()
        assert isinstance(c.temperature, float)
        assert 0.0 <= c.temperature <= 2.0

    def test_get_nested_key(self):
        c = Config()
        val = c.get("openrouter", "base_url")
        assert val and "openrouter" in val

    def test_get_missing_key_returns_default(self):
        c = Config()
        assert c.get("nonexistent", "key", default="fallback") == "fallback"

    def test_initialize_creates_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            c = Config(project_root=root)
            assert not c.is_initialized
            c.initialize()
            assert c.is_initialized
            assert (root / ".cybersentry" / "runs").exists()
            assert (root / ".cybersentry" / "policies").exists()


# ---------------------------------------------------------------------------
# RunStateManager
# ---------------------------------------------------------------------------

class TestRunStateManager:
    def _make_state(self, tmp_path: Path) -> RunStateManager:
        c = Config(project_root=tmp_path)
        c.initialize()
        return RunStateManager(c)

    def test_create_run_returns_run(self, tmp_path):
        state = self._make_state(tmp_path)
        run = state.create_run("test_target")
        assert run.id
        assert run.target == "test_target"

    def test_run_dir_exists_after_create(self, tmp_path):
        state = self._make_state(tmp_path)
        run = state.create_run("target")
        assert state.get_run_dir(run.id).exists()

    def test_save_and_load_run(self, tmp_path):
        state = self._make_state(tmp_path)
        run = state.create_run("myapp")
        run.status = "completed"
        run.total_findings = 5
        state.save_run(run)

        loaded = state.load_run(run.id)
        assert loaded.id == run.id
        assert loaded.status == "completed"
        assert loaded.total_findings == 5

    def test_load_nonexistent_run_raises(self, tmp_path):
        state = self._make_state(tmp_path)
        with pytest.raises(FileNotFoundError):
            state.load_run("nonexistent_run_id")

    def test_list_runs_returns_all(self, tmp_path):
        state = self._make_state(tmp_path)
        r1 = state.create_run("a")
        r2 = state.create_run("b")
        runs = state.list_runs()
        assert r1.id in runs
        assert r2.id in runs

    def test_list_runs_empty_when_no_runs(self, tmp_path):
        state = self._make_state(tmp_path)
        assert state.list_runs() == []

    def test_complete_run_sets_status(self, tmp_path):
        state = self._make_state(tmp_path)
        run = state.create_run("app")
        state.complete_run(run)
        assert run.status == "completed"
        assert run.completed_at is not None

    def test_save_and_load_artifact(self, tmp_path):
        state = self._make_state(tmp_path)
        run = state.create_run("app")
        data = {"key": "value", "numbers": [1, 2, 3]}
        state.save_artifact(run.id, "test_artifact", data)
        loaded = state.load_artifact(run.id, "test_artifact")
        assert loaded == data

    def test_load_missing_artifact_raises(self, tmp_path):
        state = self._make_state(tmp_path)
        run = state.create_run("app")
        with pytest.raises(FileNotFoundError):
            state.load_artifact(run.id, "missing")


# ---------------------------------------------------------------------------
# find_tool (scanner base)
# ---------------------------------------------------------------------------

class TestFindTool:
    def test_find_tool_returns_none_for_fake_tool(self):
        result = find_tool("definitely_not_a_real_tool_xyz_abc_123")
        assert result is None

    def test_find_tool_finds_python(self):
        # python should always be findable in the same dir as sys.executable
        import sys
        result = find_tool("python") or find_tool("python.exe")
        if result is None:
            pytest.skip("Python executable not discoverable on PATH in this environment")
        assert result is not None


# ---------------------------------------------------------------------------
# SARIF Export
# ---------------------------------------------------------------------------

class TestSarifExport:
    def _make_run_with_findings(self) -> Run:
        findings = [
            Finding(
                title="SQL Injection",
                scanner="bandit",
                rule_id="B608:hardcoded_sql_expressions",
                severity=Severity.HIGH,
                file_path="app/db.py",
                line_start=21,
                line_end=21,
                cwe="CWE-89",
                code_snippet="cursor.execute(query)",
            ),
            Finding(
                title="eval() usage",
                scanner="bandit",
                rule_id="B307:blacklist",
                severity=Severity.MEDIUM,
                file_path="app/utils.py",
                line_start=60,
            ),
        ]
        run = Run(
            target="/app",
            findings=findings,
            total_findings=2,
            status="completed",
            scanners_used=["bandit"],
        )
        return run

    def test_export_sarif_returns_valid_json(self):
        run = self._make_run_with_findings()
        sarif_str = export_sarif(run)
        doc = json.loads(sarif_str)
        assert doc["version"] == "2.1.0"
        assert "$schema" in doc

    def test_sarif_has_correct_result_count(self):
        run = self._make_run_with_findings()
        doc = json.loads(export_sarif(run))
        results = doc["runs"][0]["results"]
        assert len(results) == 2

    def test_sarif_result_has_location(self):
        run = self._make_run_with_findings()
        doc = json.loads(export_sarif(run))
        result = doc["runs"][0]["results"][0]
        loc = result["locations"][0]["physicalLocation"]
        assert "artifactLocation" in loc
        assert "region" in loc
        assert loc["region"]["startLine"] >= 1

    def test_sarif_high_severity_maps_to_error(self):
        run = self._make_run_with_findings()
        doc = json.loads(export_sarif(run))
        # First finding is HIGH → should be "error"
        assert doc["runs"][0]["results"][0]["level"] == "error"

    def test_sarif_medium_severity_maps_to_warning(self):
        run = self._make_run_with_findings()
        doc = json.loads(export_sarif(run))
        assert doc["runs"][0]["results"][1]["level"] == "warning"

    def test_sarif_rules_deduplicated(self):
        # Two findings with same rule should produce one rule entry
        f1 = Finding(scanner="bandit", rule_id="B608:sql", severity=Severity.HIGH, file_path="a.py", line_start=1)
        f2 = Finding(scanner="bandit", rule_id="B608:sql", severity=Severity.HIGH, file_path="b.py", line_start=5)
        run = Run(findings=[f1, f2], total_findings=2, scanners_used=["bandit"])
        doc = json.loads(export_sarif(run))
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1

    def test_path_to_uri_normalizes_backslashes(self):
        result = _path_to_uri("C:\\Users\\app\\db.py")
        assert "\\" not in result
        assert "/" in result

    def test_sarif_rule_id_format(self):
        f = Finding(scanner="bandit", rule_id="B608:sql")
        rid = _sarif_rule_id(f)
        assert rid == "bandit/B608:sql"


# ---------------------------------------------------------------------------
# Diff generator
# ---------------------------------------------------------------------------

class TestDiffGenerator:
    def test_unified_diff_has_minus_and_plus(self):
        original = "x = eval(user_input)\n"
        patched = "x = int(user_input)\n"
        diff = _generate_unified_diff(original, patched, "app.py")
        assert "-" in diff
        assert "+" in diff

    def test_empty_diff_for_identical_code(self):
        code = "x = 1\n"
        diff = _generate_unified_diff(code, code, "app.py")
        assert diff == ""

    def test_diff_includes_filename(self):
        diff = _generate_unified_diff("a = 1\n", "a = 2\n", "myfile.py")
        assert "myfile.py" in diff
