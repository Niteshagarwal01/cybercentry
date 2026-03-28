# pyre-unsafe
"""Run state manager — manages run directories and JSON artifact persistence."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from cyber_sentry_cli.core.config import Config
from cyber_sentry_cli.core.models import Run


class RunStateManager:
    """Creates run directories, saves / loads JSON artifacts, generates run IDs."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.runs_dir = config.runs_dir

    def create_run(self, target: str) -> Run:
        """Create a new run and its directory."""
        run = Run(target=target)
        run_dir = self.runs_dir / run.id
        run_dir.mkdir(parents=True, exist_ok=True)
        self._save_run(run)
        return run

    def get_run_dir(self, run_id: str) -> Path:
        return self.runs_dir / run_id

    def save_run(self, run: Run) -> None:
        self._save_run(run)

    def load_run(self, run_id: str) -> Run:
        run_dir = self.runs_dir / run_id
        run_file = run_dir / "run.json"
        if not run_file.exists():
            raise FileNotFoundError(f"Run not found: {run_id}")
        data = json.loads(run_file.read_text(encoding="utf-8"))
        return Run.model_validate(data)

    def list_runs(self) -> list[str]:
        """List all run IDs sorted by most recent first."""
        if not self.runs_dir.exists():
            return []
        runs: list[tuple[datetime, str]] = []
        for d in self.runs_dir.iterdir():
            run_file = d / "run.json"
            if not d.is_dir() or not run_file.exists():
                continue

            started_at = datetime.min.replace(tzinfo=timezone.utc)
            try:
                data = json.loads(run_file.read_text(encoding="utf-8"))
                started_raw = data.get("started_at")
                if started_raw:
                    started_at = datetime.fromisoformat(started_raw.replace("Z", "+00:00"))
            except Exception:
                # Fall back to file modification time if run.json cannot be parsed.
                started_at = datetime.fromtimestamp(run_file.stat().st_mtime, tz=timezone.utc)

            runs.append((started_at, d.name))

        runs.sort(key=lambda item: (item[0], item[1]), reverse=True)
        return [run_id for _, run_id in runs]

    def complete_run(self, run: Run) -> None:
        """Mark a run as completed."""
        run.completed_at = datetime.now(timezone.utc)
        run.status = "completed"
        self._save_run(run)

    def fail_run(self, run: Run, error: str = "") -> None:
        """Mark a run as failed."""
        run.completed_at = datetime.now(timezone.utc)
        run.status = "failed"
        self._save_run(run)

    # -- persistence --------------------------------------------------------

    def _save_run(self, run: Run) -> None:
        run_dir = self.runs_dir / run.id
        run_dir.mkdir(parents=True, exist_ok=True)
        run_file = run_dir / "run.json"
        run_file.write_text(
            run.model_dump_json(indent=2),
            encoding="utf-8",
        )

    def save_artifact(self, run_id: str, name: str, data: dict | list) -> Path:
        """Save an arbitrary JSON artifact to the run directory."""
        run_dir = self.runs_dir / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = run_dir / f"{name}.json"
        artifact_path.write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8",
        )
        return artifact_path

    def load_artifact(self, run_id: str, name: str) -> dict | list:
        """Load a JSON artifact from the run directory."""
        artifact_path = self.runs_dir / run_id / f"{name}.json"
        if not artifact_path.exists():
            raise FileNotFoundError(f"Artifact not found: {run_id}/{name}.json")
        return json.loads(artifact_path.read_text(encoding="utf-8"))
