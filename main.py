#!/usr/bin/env python3
"""
SENTINEL Sovereign Core v3.0 — Master Orchestrator & Process Supervisor

Coordinates:
  1. FastAPI Privacy Shield Service (Presidio NLP + Surgical Redaction) on port 8000
  2. Node.js / TypeScript Core Security API on port 5001
  3. React + Vite Web Client on port 5173

Handles environment configuration, process supervision, health checking,
and atomic graceful shutdown.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
SERVER_DIR = ROOT_DIR / "server"
PRIVACY_DIR = ROOT_DIR / "privacy-service"
CLIENT_DIR = ROOT_DIR / "client"
ENV_FILE = ROOT_DIR / ".env"

CHILD_PROCESSES: list[subprocess.Popen] = []


def load_env() -> dict[str, str]:
    """Parse .env file into os.environ without requiring third-party libraries."""
    env_vars: dict[str, str] = {}
    if not ENV_FILE.exists():
        return env_vars

    with open(ENV_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            env_vars[key] = val
            if key not in os.environ:
                os.environ[key] = val
    return env_vars


def get_python_exe() -> str:
    """Resolve the active Python executable, preferring the uv-managed venv."""
    venv_python = ROOT_DIR / ".venv" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python)
    return sys.executable


def signal_handler(signum, frame):
    """Graceful termination for all supervised child processes."""
    print("\n[sentinel-supervisor] Received shutdown signal. Terminating all subsystems...")
    for proc in reversed(CHILD_PROCESSES):
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
    print("[sentinel-supervisor] All services stopped cleanly.")
    sys.exit(0)


def check_health(url: str, timeout: float = 1.0) -> bool:
    try:
        req = urllib.request.Request(url, headers={"Host": "127.0.0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return res.status == 200
    except (urllib.error.URLError, ConnectionResetError, TimeoutError, Exception):
        return False


def start_privacy_service(dev: bool = False) -> subprocess.Popen:
    python_exe = get_python_exe()
    port = os.environ.get("PRIVACY_PORT", "8000")
    host = os.environ.get("PRIVACY_HOST", "127.0.0.1")

    cmd = [
        python_exe,
        "-m",
        "uvicorn",
        "main:app",
        "--host",
        host,
        "--port",
        port,
    ]
    if dev:
        cmd.append("--reload")

    print(f"[sentinel-supervisor] Starting Privacy Shield on http://{host}:{port}...")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PRIVACY_DIR)
    proc = subprocess.Popen(cmd, cwd=str(PRIVACY_DIR), env=env)
    CHILD_PROCESSES.append(proc)
    return proc


def start_server_api(dev: bool = False) -> subprocess.Popen:
    port = os.environ.get("SENTINEL_PORT", "5001")
    host = os.environ.get("HOST", "127.0.0.1")

    if dev:
        cmd = ["npx", "tsx", "src/server.ts", port]
    else:
        # Check if dist/server.js exists, otherwise build it
        dist_server = SERVER_DIR / "dist" / "server.js"
        if not dist_server.exists():
            print("[sentinel-supervisor] Compiling TypeScript server...")
            subprocess.run(["npm", "run", "build"], cwd=str(SERVER_DIR), check=True)
        cmd = ["node", "dist/server.js", port]

    print(f"[sentinel-supervisor] Starting Core Security API on http://{host}:{port}...")
    env = os.environ.copy()
    env["PYTHON_EXECUTABLE"] = get_python_exe()
    proc = subprocess.Popen(cmd, cwd=str(SERVER_DIR), env=env)
    CHILD_PROCESSES.append(proc)
    return proc


def start_client_ui() -> subprocess.Popen:
    print("[sentinel-supervisor] Starting React + Vite UI on http://localhost:5173...")
    cmd = ["npm", "run", "dev"]
    proc = subprocess.Popen(cmd, cwd=str(CLIENT_DIR), env=os.environ.copy())
    CHILD_PROCESSES.append(proc)
    return proc


def run_tests() -> int:
    print("\n=======================================================")
    print(" 1. Running Privacy Shield PyTest Suite")
    print("=======================================================")
    python_exe = get_python_exe()
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PRIVACY_DIR)
    res_py = subprocess.run([python_exe, "-m", "pytest"], cwd=str(PRIVACY_DIR), env=env)

    print("\n=======================================================")
    print(" 2. Running Core API Acceptance Test Suite (79 Tests)")
    print("=======================================================")
    res_ts = subprocess.run(["npm", "test"], cwd=str(SERVER_DIR))

    if res_py.returncode == 0 and res_ts.returncode == 0:
        print("\n[✔] ALL TEST SUITES PASSED CLEANLY.")
        return 0
    else:
        print("\n[✖] TEST SUITE FAILURES DETECTED.")
        return 1


def run_fuzz() -> int:
    print("\n[sentinel-fuzzer] Running 5,000-case ZIP Mutation Fuzzer...")
    res = subprocess.run(["npm", "run", "fuzz:archive"], cwd=str(SERVER_DIR))
    return res.returncode


def run_calibrate() -> int:
    print("\n[sentinel-calibration] Running Analyzer Trust & Calibration Harness...")
    res = subprocess.run(["npm", "run", "calibrate"], cwd=str(SERVER_DIR))
    return res.returncode


def main():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    load_env()

    parser = argparse.ArgumentParser(
        description="SENTINEL Sovereign Core v3.0 — Master Process Supervisor"
    )
    parser.add_argument("--dev", action="store_true", help="Start in development mode with hot-reloading")
    parser.add_argument("--server-only", action="store_true", help="Start backend services only (no web UI)")
    parser.add_argument("--test", action="store_true", help="Run full acceptance test suites (Python + TypeScript)")
    parser.add_argument("--fuzz", action="store_true", help="Run 5,000-case archive mutation fuzzer")
    parser.add_argument("--calibrate", action="store_true", help="Run analyzer trust & calibration lab")
    parser.add_argument("--health", action="store_true", help="Probe running daemon health")

    args = parser.parse_args()

    if args.test:
        sys.exit(run_tests())
    if args.fuzz:
        sys.exit(run_fuzz())
    if args.calibrate:
        sys.exit(run_calibrate())
    if args.health:
        server_ok = check_health("http://127.0.0.1:5001/api/health")
        privacy_ok = check_health("http://127.0.0.1:8000/ping")
        print(f"Server API (5001):   {'ONLINE' if server_ok else 'OFFLINE'}")
        print(f"Privacy Shield (8000): {'ONLINE' if privacy_ok else 'OFFLINE'}")
        sys.exit(0 if (server_ok and privacy_ok) else 1)

    print("==================================================================")
    print("       SENTINEL Sovereign Core v3.0 — Bootstrapping Services       ")
    print("==================================================================")

    # 1. Start Privacy Shield
    start_privacy_service(dev=args.dev)

    # Wait for Privacy Shield readiness
    for _ in range(30):
        if check_health("http://127.0.0.1:8000/ping"):
            print("[✔] Privacy Shield is ready on port 8000.")
            break
        time.sleep(0.3)

    # 2. Start Core API Server
    start_server_api(dev=args.dev)

    # Wait for Server readiness
    for _ in range(30):
        if check_health("http://127.0.0.1:5001/api/health"):
            print("[✔] Core Security API is ready on port 5001.")
            break
        time.sleep(0.3)

    # 3. Start Client UI if requested
    if not args.server_only:
        start_client_ui()

    print("\n[✔] SENTINEL Sovereign Core is operational.")
    print("    - Web Client:     http://localhost:5173")
    print("    - REST API:       http://127.0.0.1:5001/api/health")
    print("    - Privacy Engine: http://127.0.0.1:8000/ping")
    print("\nPress Ctrl+C to terminate all services.\n")

    # Keep main thread alive and supervise children
    try:
        while True:
            time.sleep(1)
            for proc in CHILD_PROCESSES:
                if proc.poll() is not None:
                    print(f"[!] Warning: Supervised process (PID {proc.pid}) exited unexpectedly.")
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)


if __name__ == "__main__":
    main()
