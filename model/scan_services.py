import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional

from logging_utils import configure_logger, get_job_logger
from result_utils import attach_result_comparison, normalize_result_schema


ProgressCallback = Callable[[int], None]
ScanRunner = Callable[[ProgressCallback, Any], Dict[str, Any]]
CompletionCallback = Callable[[str, Dict[str, Any], Dict[str, Any]], None]


class JobStore:
    """SQLite-backed tracking for active/completed jobs plus progress events."""

    def __init__(self, module_name: str, target_field: str, database_path: str | Path):
        self.module_name = module_name
        self.target_field = target_field
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._ensure_schema()

    @property
    def active(self) -> Dict[str, dict]:
        return {job["job_id"]: job for job in self.list_jobs(status="running")}

    @property
    def completed(self) -> Dict[str, dict]:
        jobs = self.list_jobs(statuses=("completed", "failed"), newest_first=False)
        return {job["job_id"]: job for job in jobs}

    def create(
        self,
        target_value: str,
        initial_fields: Optional[Dict[str, Any]] = None,
    ) -> str:
        job_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        metadata = dict(initial_fields or {})

        with self._write_connection() as connection:
            connection.execute(
                """
                INSERT INTO jobs (
                    job_id,
                    module_name,
                    target_field,
                    target_value,
                    status,
                    progress,
                    started_at,
                    metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    self.module_name,
                    self.target_field,
                    target_value,
                    "running",
                    0,
                    now,
                    json.dumps(metadata, ensure_ascii=False),
                ),
            )
            snapshot = self.get(job_id, include_results=False, connection=connection)
            self._insert_event(
                connection,
                job_id,
                "created",
                {
                    "job_id": job_id,
                    "module": self.module_name,
                    "status": "running",
                    "progress": 0,
                    "job": snapshot,
                },
            )

        return job_id

    def update_progress(
        self,
        job_id: str,
        progress: int,
        *,
        message: str | None = None,
        details: Dict[str, Any] | None = None,
    ) -> None:
        safe_progress = max(0, min(100, int(progress)))
        payload = {
            "job_id": job_id,
            "module": self.module_name,
            "status": "running",
            "progress": safe_progress,
        }
        if message:
            payload["message"] = message
        if details:
            payload["details"] = details

        with self._write_connection() as connection:
            connection.execute(
                "UPDATE jobs SET progress = ? WHERE job_id = ?",
                (safe_progress, job_id),
            )
            snapshot = self.get(job_id, include_results=False, connection=connection)
            if snapshot:
                payload["job"] = snapshot
            self._insert_event(connection, job_id, "progress", payload)

    def publish_event(self, job_id: str, event_type: str, payload: Dict[str, Any]) -> None:
        with self._write_connection() as connection:
            self._insert_event(connection, job_id, event_type, payload)

    def complete(self, job_id: str, results: Dict[str, Any]) -> dict:
        now = datetime.now(UTC).isoformat()
        results_json = json.dumps(results, ensure_ascii=False)
        results_file = results.get("output_file")

        with self._write_connection() as connection:
            connection.execute(
                """
                UPDATE jobs
                SET status = ?, completed_at = ?, progress = ?, error = NULL,
                    results_json = ?, results_file = ?
                WHERE job_id = ?
                """,
                ("completed", now, 100, results_json, results_file, job_id),
            )
            connection.execute(
                """
                INSERT INTO job_results (job_id, module_name, target_value, result_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    result_json = excluded.result_json,
                    created_at = excluded.created_at
                """,
                (
                    job_id,
                    self.module_name,
                    self._target_value_for_job(job_id, connection),
                    results_json,
                    now,
                ),
            )
            completed_job = self.get(job_id, include_results=True, connection=connection)
            self._insert_event(
                connection,
                job_id,
                "completed",
                {
                    "job_id": job_id,
                    "module": self.module_name,
                    "status": "completed",
                    "progress": 100,
                    "job": completed_job,
                },
            )
            return completed_job or {"job_id": job_id}

    def update_results(self, job_id: str, results: Dict[str, Any]) -> dict:
        results_json = json.dumps(results, ensure_ascii=False)
        results_file = results.get("output_file")

        with self._write_connection() as connection:
            connection.execute(
                """
                UPDATE jobs
                SET results_json = ?, results_file = ?
                WHERE job_id = ?
                """,
                (results_json, results_file, job_id),
            )
            connection.execute(
                """
                INSERT INTO job_results (job_id, module_name, target_value, result_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    result_json = excluded.result_json,
                    created_at = excluded.created_at
                """,
                (
                    job_id,
                    self.module_name,
                    self._target_value_for_job(job_id, connection),
                    results_json,
                    datetime.now(UTC).isoformat(),
                ),
            )
            return self.get(job_id, include_results=True, connection=connection) or {
                "job_id": job_id
            }

    def fail(self, job_id: str, error: str) -> dict:
        now = datetime.now(UTC).isoformat()
        with self._write_connection() as connection:
            connection.execute(
                """
                UPDATE jobs
                SET status = ?, completed_at = ?, error = ?
                WHERE job_id = ?
                """,
                ("failed", now, error, job_id),
            )
            failed_job = self.get(job_id, include_results=False, connection=connection)
            self._insert_event(
                connection,
                job_id,
                "failed",
                {
                    "job_id": job_id,
                    "module": self.module_name,
                    "status": "failed",
                    "error": error,
                    "job": failed_job,
                },
            )
            return failed_job or {"job_id": job_id}

    def get(
        self,
        job_id: str,
        *,
        include_results: bool = True,
        connection: sqlite3.Connection | None = None,
    ) -> dict | None:
        row = self._select_job_row(job_id, connection=connection)
        if row is None:
            return None
        return self._row_to_job_dict(row, include_results=include_results)

    def list_jobs(
        self,
        *,
        status: str | None = None,
        statuses: Iterable[str] | None = None,
        limit: int | None = 200,
        newest_first: bool = True,
    ) -> list[dict]:
        params: list[Any] = [self.module_name]
        query = """
            SELECT *
            FROM jobs
            WHERE module_name = ?
        """

        if status:
            query += " AND status = ?"
            params.append(status)
        elif statuses:
            normalized_statuses = list(statuses)
            placeholders = ", ".join("?" for _ in normalized_statuses)
            query += f" AND status IN ({placeholders})"
            params.extend(normalized_statuses)

        ordering = "DESC" if newest_first else "ASC"
        query += f" ORDER BY started_at {ordering}"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        with self._read_connection() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._row_to_job_dict(row, include_results=True) for row in rows]

    def get_latest_completed_job(self, target_value: str | None = None) -> dict | None:
        params: list[Any] = [self.module_name]
        query = """
            SELECT *
            FROM jobs
            WHERE module_name = ? AND status = 'completed'
        """
        if target_value:
            query += " AND target_value = ?"
            params.append(target_value)
        query += " ORDER BY completed_at DESC LIMIT 1"

        with self._read_connection() as connection:
            row = connection.execute(query, params).fetchone()
        return self._row_to_job_dict(row, include_results=True) if row else None

    def get_previous_completed_job(self, job_id: str) -> dict | None:
        with self._read_connection() as connection:
            current_row = self._select_job_row(job_id, connection=connection)
            if current_row is None:
                return None

            row = connection.execute(
                """
                SELECT *
                FROM jobs
                WHERE module_name = ?
                  AND target_value = ?
                  AND status = 'completed'
                  AND job_id != ?
                ORDER BY completed_at DESC
                LIMIT 1
                """,
                (
                    self.module_name,
                    current_row["target_value"],
                    job_id,
                ),
            ).fetchone()
        return self._row_to_job_dict(row, include_results=True) if row else None

    def get_events_after(self, job_id: str, after_event_id: int = 0) -> list[dict]:
        with self._read_connection() as connection:
            rows = connection.execute(
                """
                SELECT event_id, event_type, event_json, created_at
                FROM job_events
                WHERE job_id = ? AND event_id > ?
                ORDER BY event_id ASC
                """,
                (job_id, after_event_id),
            ).fetchall()

        events = []
        for row in rows:
            payload = self._load_json(row["event_json"], default={})
            events.append(
                {
                    "event_id": row["event_id"],
                    "event": row["event_type"],
                    "created_at": row["created_at"],
                    "data": payload,
                }
            )
        return events

    def get_latest_event_id(self, job_id: str) -> int:
        with self._read_connection() as connection:
            row = connection.execute(
                "SELECT MAX(event_id) AS event_id FROM job_events WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        return int((row or {}).get("event_id") or 0)

    def _ensure_schema(self) -> None:
        with self._write_connection() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    module_name TEXT NOT NULL,
                    target_field TEXT NOT NULL,
                    target_value TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    error TEXT,
                    results_json TEXT,
                    results_file TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS job_results (
                    job_id TEXT PRIMARY KEY,
                    module_name TEXT NOT NULL,
                    target_value TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS job_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_jobs_module_status
                    ON jobs (module_name, status, started_at);
                CREATE INDEX IF NOT EXISTS idx_jobs_module_target
                    ON jobs (module_name, target_value, completed_at);
                CREATE INDEX IF NOT EXISTS idx_job_events_job
                    ON job_events (job_id, event_id);
                """
            )

    def _row_to_job_dict(self, row: sqlite3.Row, *, include_results: bool) -> dict:
        metadata = self._load_json(row["metadata_json"], default={})
        job = {
            "job_id": row["job_id"],
            "module": row["module_name"],
            row["target_field"]: row["target_value"],
            "status": row["status"],
            "progress": row["progress"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "results_file": row["results_file"],
        }
        job.update(metadata)

        if row["error"]:
            job["error"] = row["error"]

        if include_results and row["results_json"]:
            job["results"] = self._load_json(row["results_json"], default={})

        return job

    def _insert_event(
        self,
        connection: sqlite3.Connection,
        job_id: str,
        event_type: str,
        payload: Dict[str, Any],
    ) -> None:
        connection.execute(
            """
            INSERT INTO job_events (job_id, module_name, event_type, event_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                job_id,
                self.module_name,
                event_type,
                json.dumps(payload, ensure_ascii=False),
                datetime.now(UTC).isoformat(),
            ),
        )

    def _select_job_row(
        self,
        job_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> sqlite3.Row | None:
        if connection is not None:
            return connection.execute(
                "SELECT * FROM jobs WHERE job_id = ? AND module_name = ?",
                (job_id, self.module_name),
            ).fetchone()

        with self._read_connection() as owned_connection:
            return owned_connection.execute(
                "SELECT * FROM jobs WHERE job_id = ? AND module_name = ?",
                (job_id, self.module_name),
            ).fetchone()

    def _target_value_for_job(
        self,
        job_id: str,
        connection: sqlite3.Connection,
    ) -> str:
        row = connection.execute(
            "SELECT target_value FROM jobs WHERE job_id = ? AND module_name = ?",
            (job_id, self.module_name),
        ).fetchone()
        return row["target_value"] if row else ""

    @contextmanager
    def _read_connection(self):
        connection = sqlite3.connect(self.database_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _write_connection(self):
        connection = sqlite3.connect(self.database_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _load_json(self, raw_value: str | None, *, default: Any) -> Any:
        if not raw_value:
            return deepcopy(default)
        try:
            return json.loads(raw_value)
        except json.JSONDecodeError:
            return deepcopy(default)


class ScanModuleService:
    """Background execution and SQLite-backed job tracking for a scan module."""

    def __init__(
        self,
        module_name: str,
        target_field: str,
        logger_name: Optional[str] = None,
        database_path: str | Path = "results/scan_jobs.sqlite3",
    ):
        self.module_name = module_name
        self.target_field = target_field
        self.jobs = JobStore(module_name, target_field, database_path)
        self.logger = configure_logger(logger_name or f"{module_name}.service")

    @property
    def active_jobs(self) -> Dict[str, dict]:
        return self.jobs.active

    @property
    def completed_jobs(self) -> Dict[str, dict]:
        return self.jobs.completed

    def start_job(
        self,
        *,
        target_value: str,
        runner: ScanRunner,
        initial_fields: Optional[Dict[str, Any]] = None,
        on_complete: Optional[CompletionCallback] = None,
    ) -> str:
        initial_fields = dict(initial_fields or {})
        job_id = self.jobs.create(target_value, initial_fields=initial_fields)
        job_logger = get_job_logger(
            self.logger,
            module_name=self.module_name,
            job_id=job_id,
        )

        def update_progress(progress: int) -> None:
            self.jobs.update_progress(job_id, progress)

        def run_job() -> None:
            try:
                job_logger.info("Starting scan")
                self.jobs.publish_event(
                    job_id,
                    "log",
                    {
                        "job_id": job_id,
                        "module": self.module_name,
                        "message": "Starting scan",
                    },
                )
                results = runner(update_progress, job_logger)
                normalized_results = normalize_result_schema(
                    self.module_name,
                    results,
                    profile_name=str(initial_fields.get("profile", "standard")),
                    job_context={"job_id": job_id},
                )

                previous_result_job = self.jobs.get_previous_completed_job(job_id)
                previous_result = (
                    previous_result_job.get("results") if previous_result_job else None
                )
                attach_result_comparison(
                    normalized_results,
                    previous_result,
                    baseline_job_id=(
                        previous_result_job.get("job_id")
                        if previous_result_job
                        else None
                    ),
                )
                normalized_results["comparison"] = normalized_results.get(
                    "comparison", {}
                )
                normalized_results["comparison"].setdefault(
                    "current_job_id",
                    job_id,
                )
                normalized_results["comparison"].setdefault(
                    "baseline_job_id",
                    previous_result_job.get("job_id")
                    if previous_result_job
                    else None,
                )
                normalized_results.setdefault("summary", {})
                normalized_results["summary"]["comparison"] = normalized_results[
                    "comparison"
                ].get("summary", {})
                self._sync_output_file(normalized_results)

                completed_job = self.jobs.complete(job_id, normalized_results)
                job_logger.info("Scan completed successfully")
            except Exception as exc:
                self.jobs.fail(job_id, str(exc))
                job_logger.exception("Scan failed")
                return

            if on_complete:
                try:
                    on_complete(job_id, completed_job, normalized_results)
                    normalized_results.setdefault("summary", {})
                    normalized_results["summary"]["comparison"] = normalized_results.get(
                        "comparison", {}
                    ).get("summary", {})
                    self._sync_output_file(normalized_results)
                    completed_job = self.jobs.update_results(job_id, normalized_results)
                except Exception:
                    job_logger.exception("Post-processing failed")

        thread = threading.Thread(
            target=run_job,
            daemon=True,
            name=f"{self.module_name}-{job_id[:8]}",
        )
        thread.start()
        return job_id

    def get_job(self, job_id: str, *, include_results: bool = True) -> dict | None:
        return self.jobs.get(job_id, include_results=include_results)

    def list_jobs(
        self,
        *,
        status: str | None = None,
        statuses: Iterable[str] | None = None,
        limit: int | None = 200,
        newest_first: bool = True,
    ) -> list[dict]:
        return self.jobs.list_jobs(
            status=status,
            statuses=statuses,
            limit=limit,
            newest_first=newest_first,
        )

    def latest_completed_job(self, target_value: str | None = None) -> dict | None:
        return self.jobs.get_latest_completed_job(target_value)

    def events_after(self, job_id: str, after_event_id: int = 0) -> list[dict]:
        return self.jobs.get_events_after(job_id, after_event_id)

    def _sync_output_file(self, results: Dict[str, Any]) -> None:
        output_file = results.get("output_file")
        if not output_file:
            return

        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(results, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            self.logger.exception("Failed to sync normalized output file")
