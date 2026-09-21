#!/usr/bin/env python3
"""Lab-only: run TerminalApp or UserApp in this tmux pane with env from the lab JSON.

Production Java never reads the lab file. On owner or client change this process
SIGTERMs the child JVM and starts it again with USB_SERIAL_PORT / NODE_* rewritten.
The pane (title, split, id) does not change.

The child is started in its own session so it is not in the tmux pane's process
group. This wrapper therefore handles SIGHUP (tmux pane teardown) and kills that
process group; otherwise the JVM outlives the pane and holds the node's terminal
gateway.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

POLL_S = 0.2
DEFAULT_LAB = "/tmp/otp-keychain-lab.json"

CLIENT1 = "client-1"
CLIENT2 = "client-2"
MODE_USER = "USER"
MODE_SAE = "SAE"

DEFAULT_NODES = {
    CLIENT1: {
        "host": "127.0.0.1",
        "nativePort": 11111,
        "terminalPort": 11112,
        "serialPort": "/tmp/ttyACM-se1",
    },
    CLIENT2: {
        "host": "127.0.0.1",
        "nativePort": 5020,
        "terminalPort": 11113,
        "serialPort": "/tmp/ttyACM-se2",
    },
}


def token(raw: str) -> str:
    return raw.strip().upper().replace("-", " ").replace("_", " ")


def normalize_client(client_in: str) -> str:
    cl = client_in.strip().lower().replace("_", "-").replace(" ", "-")
    if cl in {CLIENT2, "client2", "cl-2", "cl2", "sae-2", "sae2", "2"}:
        return CLIENT2
    return CLIENT1


def normalize(raw: dict[str, Any] | None) -> dict[str, Any] | None:
    if not raw:
        return None
    mode_in = raw.get("mode") or ""
    client_in = str(raw.get("client") or "")
    t = token(str(mode_in))
    if t in {"CLIENT1", "CLIENT 1", "CL1", "CL 1", "C1", "SAE1", "SAE 1"}:
        mode, client = MODE_SAE, CLIENT1
    elif t in {"CLIENT2", "CLIENT 2", "CL2", "CL 2", "C2", "SAE2", "SAE 2"}:
        mode, client = MODE_SAE, CLIENT2
    elif t in {"SAE", "TERM", "TERMINAL", "T"}:
        mode, client = MODE_SAE, normalize_client(client_in)
    else:
        mode, client = MODE_USER, normalize_client(client_in)

    nodes_in = raw.get("nodes") or {}
    node = None
    for key in (client, "sae-1" if client == CLIENT1 else "sae-2"):
        if key in nodes_in:
            node = nodes_in[key]
            break
    defaults = DEFAULT_NODES[client]
    if not isinstance(node, dict):
        node = {}
    host = str(node.get("host") or defaults["host"]).strip() or defaults["host"]
    native = int(node.get("nativePort") or defaults["nativePort"])
    terminal = int(node.get("terminalPort") or defaults["terminalPort"])
    serial = str(node.get("serialPort") or defaults["serialPort"]).strip() or defaults["serialPort"]
    return {
        "mode": mode,
        "client": client,
        "host": host,
        "nativePort": native,
        "terminalPort": terminal,
        "serialPort": serial,
    }


def fingerprint(state: dict[str, Any]) -> tuple[Any, ...]:
    return (
        state["mode"],
        state["client"],
        state["serialPort"],
        state["host"],
        state["nativePort"],
        state["terminalPort"],
    )


def read_lab(path: Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    if not text.strip():
        return None
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, dict):
        return None
    return normalize(raw)


def role_owns(role: str, state: dict[str, Any]) -> bool:
    if role == "terminal":
        return state["mode"] == MODE_SAE
    return state["mode"] == MODE_USER


def child_env(state: dict[str, Any], role: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != "USB_LAB_FILE"}
    env["USB_SERIAL_PORT"] = state["serialPort"]
    env["NODE_HOSTNAME"] = state["host"]
    env["NODE_NATIVE_PORT"] = str(state["nativePort"])
    env["NODE_TERMINAL_PORT"] = str(state["terminalPort"])
    if role == "terminal":
        env["USB_BRIDGE"] = "1"
    elif role == "userapp":
        if state["client"] == CLIENT2:
            env["USERAPP_DEVICE_CERT"] = "client2/client-cert.pem"
        else:
            env["USERAPP_DEVICE_CERT"] = "client/client-cert.pem"
    return env


def set_owner(path: Path, owner: str) -> dict[str, Any]:
    owner = owner.strip().upper()
    if owner not in {MODE_USER, MODE_SAE}:
        raise ValueError("owner must be USER or SAE")
    raw: dict[str, Any] = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                raw = loaded
        except (OSError, json.JSONDecodeError):
            raw = {}
    raw["mode"] = owner
    raw.setdefault("client", CLIENT1)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    state = normalize(raw)
    assert state is not None
    return state


def _child_pids(pid: int) -> list[int]:
    try:
        out = subprocess.check_output(["pgrep", "-P", str(pid)], text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return [int(line) for line in out.splitlines() if line.strip().isdigit()]


def _signal_tree(pid: int, sig: signal.Signals) -> None:
    for child in _child_pids(pid):
        _signal_tree(child, sig)
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        pass


def stop(proc: subprocess.Popen[Any] | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    pid = proc.pid
    # Child is its own session (start_new_session=True). Kill that group so Maven
    # and the JVM die together; pgrep -P misses an exec'd java that replaced mvn.
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        _signal_tree(pid, signal.SIGTERM)
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            _signal_tree(pid, signal.SIGKILL)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", default=os.environ.get("USB_LAB_FILE", DEFAULT_LAB))
    parser.add_argument("--role", choices=("terminal", "userapp"))
    parser.add_argument("--set-owner", choices=(MODE_USER, MODE_SAE),
                        help="write owner into the lab file and exit")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.set_owner:
        state = set_owner(Path(args.lab), args.set_owner)
        print(f"[lab-run] {args.lab} → owner={state['mode']} client={state['client']}",
              flush=True)
        return 0
    if not args.role:
        parser.error("--role is required unless --set-owner is set")
    cmd = args.command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        parser.error("missing command after --")

    lab_path = Path(args.lab)
    want = "SAE" if args.role == "terminal" else "USER"
    child: subprocess.Popen[Any] | None = None
    running_fp: tuple[Any, ...] | None = None
    last_wait = ""

    def shutdown(_signum: int | None = None, _frame: Any | None = None) -> None:
        stop(child)
        sys.exit(0)

    # tmux pane teardown sends SIGHUP, not SIGTERM. Default SIGHUP kills this
    # wrapper without touching the child session, which then outlives the pane.
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGHUP, shutdown)

    print(f"[lab-run] pane wrapper role={args.role} file={lab_path}", flush=True)
    while True:
        state = read_lab(lab_path)
        if state is None or not role_owns(args.role, state):
            stop(child)
            child = None
            running_fp = None
            msg = (
                f"[lab-run] waiting for {want}"
                + ("" if state is None else f" (now {state['mode']} {state['client']})")
            )
            if msg != last_wait:
                print(msg, flush=True)
                last_wait = msg
            time.sleep(POLL_S)
            continue

        fp = fingerprint(state)
        if child is not None and child.poll() is not None:
            print(f"[lab-run] {args.role} exited {child.returncode}; restarting", flush=True)
            child = None
            running_fp = None
            time.sleep(1)

        if child is not None and running_fp == fp:
            time.sleep(POLL_S)
            continue

        stop(child)
        print(
            f"[lab-run] start {args.role} {state['mode']} {state['client']}"
            f" serial={state['serialPort']} → {state['host']}"
            f" native={state['nativePort']} terminal={state['terminalPort']}",
            flush=True,
        )
        last_wait = ""
        child = subprocess.Popen(
            cmd,
            env=child_env(state, args.role),
            start_new_session=True,
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        running_fp = fp
        time.sleep(POLL_S)


if __name__ == "__main__":
    raise SystemExit(main())
