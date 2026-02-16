#!/usr/bin/env python3
import json
import os
import time
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
import re

RUNS_DIR = os.environ.get("RUNS_DIR", "/runs")
QUEUEDIR = Path(RUNS_DIR) / "queue"
PROCESSING = QUEUEDIR / "processing"
DONE = QUEUEDIR / "done"
STATUSDIR = Path(RUNS_DIR) / "status"

def now_ts():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def safe_name(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s or "scan")

def write_worker_status(stage: str, **extra):
    try:
        STATUSDIR.mkdir(parents=True, exist_ok=True)
        p = STATUSDIR / "worker.json"
        data = {"ts": datetime.now().isoformat(timespec="seconds"), "stage": stage}
        data.update(extra)
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass

def run_job(job_path: Path):
    job = json.loads(job_path.read_text(encoding="utf-8"))
    target = job.get("target", "").strip()
    if not target:
        raise RuntimeError("job missing target")

    job_id = job.get("job_id") or f"{safe_name(target)}_{now_ts()}"
    log_path = DONE / f"{job_id}.log"
    done_job_path = DONE / f"{job_id}.json"

    env = os.environ.copy()
    # optional overrides from UI
    overrides = job.get("env") or {}
    for k, v in overrides.items():
        env[str(k)] = str(v)

    # Run the scanner
    cmd = ["python3", "/app/site_check.py", target]

    write_worker_status("running", job_id=job_id, target=target)
    with open(log_path, "w", encoding="utf-8") as logf:
        logf.write(f"[worker] starting job_id={job_id}\n")
        logf.write(f"[worker] cmd={' '.join(cmd)}\n\n")
        logf.flush()

        p = subprocess.Popen(cmd, stdout=logf, stderr=logf, env=env)
        rc = p.wait()

        logf.write(f"\n[worker] finished rc={rc}\n")
        logf.flush()

    result = {
        "job_id": job_id,
        "target": target,
        "rc": rc,
        "finished_at": datetime.now().isoformat(timespec="seconds"),
        "log": str(log_path),
    }
    done_job_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    write_worker_status("idle", last_job=result)

def main():
    QUEUEDIR.mkdir(parents=True, exist_ok=True)
    PROCESSING.mkdir(parents=True, exist_ok=True)
    DONE.mkdir(parents=True, exist_ok=True)

    write_worker_status("idle")
    print("[worker] watching queue:", str(QUEUEDIR))

    while True:
        try:
            jobs = sorted([p for p in QUEUEDIR.glob("*.json") if p.is_file()], key=lambda p: p.stat().st_mtime)
            if not jobs:
                time.sleep(2)
                continue

            job_path = jobs[0]
            processing_path = PROCESSING / job_path.name

            try:
                shutil.move(str(job_path), str(processing_path))
            except Exception:
                time.sleep(1)
                continue

            try:
                run_job(processing_path)
            except Exception as e:
                # move failed job to DONE with error
                err = {"error": str(e), "job_file": str(processing_path)}
                (DONE / (processing_path.stem + ".error.json")).write_text(json.dumps(err, indent=2), encoding="utf-8")
            finally:
                try:
                    processing_path.unlink(missing_ok=True)
                except Exception:
                    pass

        except Exception:
            time.sleep(2)

if __name__ == "__main__":
    main()
