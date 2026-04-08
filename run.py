"""AgenticTM server launcher.

Starts uvicorn with a pre-bound socket configured with SO_REUSEADDR so the
port is immediately available again after the process stops (e.g. after Ctrl-C).
Also kills any stale process that is still holding the port before binding.

Usage:
    python run.py
    python run.py --port 8001
    python run.py --port 0           # OS picks a free port (prints it to stdout)
    python run.py --reload           # auto-reload on code changes (dev mode)
"""

from __future__ import annotations

import argparse
import faulthandler
import json
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time


# Ensure Unicode characters in log messages don't crash on Windows consoles
# (cp1252 / cp437).  Setting this early covers all print() / logging output.
if not os.environ.get("PYTHONIOENCODING"):
    os.environ["PYTHONIOENCODING"] = "utf-8:replace"

HOST = os.environ.get("AGENTICTM_HOST", "127.0.0.1")
DEFAULT_PORT = 8000


class _StatusPollAccessFilter(logging.Filter):
    """Suppress high-frequency polling noise from uvicorn access logs."""

    _status_pattern = re.compile(r'"GET /api/analysis/[^\s]+/status HTTP/1\.[01]"')

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            return self._status_pattern.search(record.getMessage()) is None
        except Exception:
            return True


def _suppress_status_poll_access_logs() -> None:
    """Keep frequent /status polls from drowning the analysis trace."""
    access_logger = logging.getLogger("uvicorn.access")
    poll_filter = _StatusPollAccessFilter()
    access_logger.addFilter(poll_filter)
    for handler in access_logger.handlers:
        handler.addFilter(poll_filter)


def _install_crash_guards() -> None:
    """Enable faulthandler so native crashes (SIGSEGV, SIGBUS, SIGABRT)
    print a Python traceback to stderr before the process dies.
    Also writes to a crash log file for post-mortem analysis.
    """
    logs_dir = os.path.join(os.path.dirname(__file__), "logs")
    os.makedirs(logs_dir, exist_ok=True)
    crash_path = os.path.join(logs_dir, "crash_traceback.log")
    try:
        crash_file = open(crash_path, "w")
        faulthandler.enable(file=crash_file, all_threads=True)
        faulthandler.enable(file=sys.stderr, all_threads=True)
        print(f"[AgenticTM] Crash guard enabled -- native tracebacks -> {crash_path}")
    except Exception as exc:
        faulthandler.enable(file=sys.stderr, all_threads=True)
        print(f"[AgenticTM] Crash guard (stderr only): {exc}", file=sys.stderr)


def _kill_port(port: int) -> None:
    """Find and terminate any process that is LISTENING on *port*."""
    if sys.platform == "win32":
        try:
            result = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and f":{port}" in parts[1] and parts[3] == "LISTENING":
                    pid = parts[4]
                    subprocess.run(
                        ["taskkill", "/F", "/PID", pid],
                        capture_output=True,
                    )
                    print(f"[run.py] Killed stale process PID {pid} holding port {port}")
                    time.sleep(0.4)
        except Exception as exc:
            print(f"[run.py] Warning: could not free port {port}: {exc}", file=sys.stderr)
        return

    lsof_path = shutil.which("lsof")
    if not lsof_path:
        return

    try:
        result = subprocess.run(
            [lsof_path, "-tiTCP:%d" % port, "-sTCP:LISTEN"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            pid = line.strip()
            if not pid:
                continue
            if int(pid) == os.getpid():
                continue
            os.kill(int(pid), signal.SIGTERM)
            print(f"[run.py] Killed stale process PID {pid} holding port {port}")
            time.sleep(0.4)
    except Exception as exc:
        print(f"[run.py] Warning: could not free port {port}: {exc}", file=sys.stderr)


def _make_socket(host: str, port: int) -> socket.socket:
    """Create a TCP socket with SO_REUSEADDR. Port 0 lets the OS pick a free port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    return sock


def main() -> None:
    _install_crash_guards()

    parser = argparse.ArgumentParser(description="Run AgenticTM server")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--reload", action="store_true",
                        help="Enable auto-reload (development mode)")
    args = parser.parse_args()

    import uvicorn

    if args.port != 0:
        _kill_port(args.port)

    sock = _make_socket(args.host, args.port)
    actual_port = sock.getsockname()[1]

    # Machine-readable line that Electron (or any parent process) can parse
    sys.stdout.write(json.dumps({
        "event": "server_ready_port",
        "port": actual_port,
        "pid": os.getpid(),
    }) + "\n")
    sys.stdout.flush()

    print(f"[AgenticTM] Listening on http://localhost:{actual_port}  (PID {os.getpid()})")
    print("[AgenticTM] Press Ctrl-C to stop\n")

    # Configure structured logging (P6)
    from agentictm.logging import configure_logging
    json_logs = os.environ.get("AGENTICTM_LOG_JSON", "").strip() in ("1", "true", "yes")
    configure_logging(json_output=json_logs)

    config = uvicorn.Config(
        "agentictm.api.server:app",
        host=args.host,
        port=actual_port,
        timeout_graceful_shutdown=2,
        timeout_keep_alive=120,
        log_level="info",
        reload=args.reload,
    )
    server = uvicorn.Server(config)
    _suppress_status_poll_access_logs()

    try:
        if args.reload:
            sock.close()
            server.run()
        else:
            server.run(sockets=[sock])
    finally:
        try:
            sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
