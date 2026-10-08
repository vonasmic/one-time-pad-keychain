#!/usr/bin/env python3
"""Lab-only: run TerminalApp or UserApp in this tmux pane with env from the lab JSON.

Production Java never reads the lab file. On owner change this process SIGTERMs the
child JVM and starts it again with USB_SERIAL_PORT rewritten. The pane (title,
split, id) does not change.

Fixed panes (--fixed-client client-1 / client-2) pin each process to one keychain.
There is no CL switch: USER gives USB to both userapps; SAE gives USB to both
terminals. Terminal panes always keep the operator gateway; userapp panes run
only while owner is USER.

--set-owner can also pin a client's serialPort (--serial client-2=auto).
lab-run then puts that path in USB_SERIAL_PORT. An explicit path is opened when
the node exists. auto / scan makes the Java CDC open search for the keychain
(USB 0483:5710), so the board need not be /dev/ttyACM0.

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
USB_OFF = "none"

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


def node_for(client: str, nodes_in: dict[str, Any] | None) -> dict[str, Any]:
    defaults = DEFAULT_NODES[client]
    node = (nodes_in or {}).get(client)
    if not isinstance(node, dict):
        node = {}
    host = str(node.get("host") or defaults["host"]).strip() or defaults["host"]
    native = int(node.get("nativePort") or defaults["nativePort"])
    terminal = int(node.get("terminalPort") or defaults["terminalPort"])
    serial = str(node.get("serialPort") or defaults["serialPort"]).strip() or defaults["serialPort"]
    return {
        "host": host,
        "nativePort": native,
        "terminalPort": terminal,
        "serialPort": serial,
    }


def normalize(raw: dict[str, Any] | None) -> dict[str, Any] | None:
    if not raw:
        return None
    mode_in = raw.get("mode") or ""
    t = token(str(mode_in))
    if t in {"SAE", "TERM", "TERMINAL", "T"}:
        mode = MODE_SAE
    else:
        mode = MODE_USER
    nodes = raw.get("nodes") if isinstance(raw.get("nodes"), dict) else {}
    return {
        "mode": mode,
        "nodes": nodes,
    }


def fingerprint(state: dict[str, Any], role: str, fixed_client: str) -> tuple[Any, ...]:
    node = node_for(fixed_client, state.get("nodes"))
    usb = usb_for(state, role, node)
    return (
        state["mode"],
        role,
        fixed_client,
        usb,
        node["host"],
        node["nativePort"],
        node["terminalPort"],
    )


def usb_for(state: dict[str, Any], role: str, node: dict[str, Any]) -> str:
    if role == "terminal":
        return node["serialPort"] if state["mode"] == MODE_SAE else USB_OFF
    return node["serialPort"] if state["mode"] == MODE_USER else USB_OFF


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
    try:
        return normalize(raw)
    except (ValueError, TypeError, KeyError):
        return None


def role_owns(role: str, state: dict[str, Any]) -> bool:
    if role == "terminal":
        # Always keep the operator gateway for concurrent key-get sync.
        return True
    return state["mode"] == MODE_USER


def child_env(
    state: dict[str, Any], role: str, fixed_client: str
) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != "USB_LAB_FILE"}
    node = node_for(fixed_client, state.get("nodes"))
    env["USB_SERIAL_PORT"] = usb_for(state, role, node)
    env["NODE_HOSTNAME"] = node["host"]
    env["NODE_NATIVE_PORT"] = str(node["nativePort"])
    env["NODE_TERMINAL_PORT"] = str(node["terminalPort"])
    if role == "userapp":
        if fixed_client == CLIENT2:
            env["USERAPP_DEVICE_CERT"] = "client2/client-cert.pem"
        else:
            env["USERAPP_DEVICE_CERT"] = "client/client-cert.pem"
    return env


def apply_serials(raw: dict[str, Any], serials: list[tuple[str, str]]) -> None:
    if not serials:
        return
    nodes = raw.get("nodes")
    if not isinstance(nodes, dict):
        nodes = {}
    else:
        nodes = dict(nodes)
    for client, port in serials:
        if client not in {CLIENT1, CLIENT2}:
            raise ValueError("serial client must be client-1 or client-2")
        port = port.strip()
        if not port:
            raise ValueError("serial path is empty")
        node = nodes.get(client)
        if not isinstance(node, dict):
            node = {}
        else:
            node = dict(node)
        node["serialPort"] = port
        nodes[client] = node
    raw["nodes"] = nodes


def set_owner(
    path: Path, owner: str, serials: list[tuple[str, str]] | None = None
) -> dict[str, Any]:
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
    # Drop legacy "client" field if present.
    raw.pop("client", None)
    apply_serials(raw, list(serials or []))
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


def serial_arg(value: str) -> tuple[str, str]:
    client, sep, port = value.partition("=")
    client = client.strip()
    port = port.strip()
    if sep != "=" or client not in {CLIENT1, CLIENT2} or not port:
        raise argparse.ArgumentTypeError(
            "expected client-1=/path or client-2=/path"
        )
    return client, port


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", default=os.environ.get("USB_LAB_FILE", DEFAULT_LAB))
    parser.add_argument("--role", choices=("terminal", "userapp"))
    parser.add_argument(
        "--fixed-client",
        required=False,
        choices=(CLIENT1, CLIENT2),
        help="pin this pane to client-1 or client-2 (required for pane wrappers)",
    )
    parser.add_argument("--set-owner", choices=(MODE_USER, MODE_SAE),
                        help="write owner into the lab file and exit")
    parser.add_argument(
        "--serial",
        action="append",
        type=serial_arg,
        default=[],
        metavar="CLIENT=PATH",
        help="with --set-owner, set that client's serialPort (repeatable)",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.serial and not args.set_owner:
        parser.error("--serial requires --set-owner")
    if args.set_owner:
        state = set_owner(Path(args.lab), args.set_owner, args.serial)
        print(f"[lab-run] {args.lab} → owner={state['mode']}", flush=True)
        for client, port in args.serial:
            print(f"[lab-run] {client} serial={port}", flush=True)
        return 0
    if not args.role:
        parser.error("--role is required unless --set-owner is set")
    if not args.fixed_client:
        parser.error("--fixed-client is required with --role")
    cmd = args.command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        parser.error("missing command after --")

    lab_path = Path(args.lab)
    fixed = args.fixed_client
    if args.role == "terminal":
        want = f"operator console ({fixed}; USB when SAE)"
    else:
        want = f"USER ({fixed})"
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

    print(
        f"[lab-run] pane wrapper role={args.role} fixed={fixed} file={lab_path}",
        flush=True,
    )
    while True:
        state = read_lab(lab_path)
        if state is None or not role_owns(args.role, state):
            stop(child)
            child = None
            running_fp = None
            msg = (
                f"[lab-run] waiting for {want}"
                + ("" if state is None else f" (now {state['mode']})")
            )
            if msg != last_wait:
                print(msg, flush=True)
                last_wait = msg
            time.sleep(POLL_S)
            continue

        fp = fingerprint(state, args.role, fixed)
        if child is not None and child.poll() is not None:
            print(f"[lab-run] {args.role} exited {child.returncode}; restarting", flush=True)
            child = None
            running_fp = None
            time.sleep(1)

        if child is not None and running_fp == fp:
            time.sleep(POLL_S)
            continue

        stop(child)
        env = child_env(state, args.role, fixed)
        print(
            f"[lab-run] start {args.role} {state['mode']} fixed={fixed}"
            + f" serial={env['USB_SERIAL_PORT']} → {env['NODE_HOSTNAME']}"
            + f" native={env['NODE_NATIVE_PORT']} terminal={env['NODE_TERMINAL_PORT']}",
            flush=True,
        )
        last_wait = ""
        child = subprocess.Popen(
            cmd,
            env=env,
            start_new_session=True,
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        running_fp = fp
        time.sleep(POLL_S)


if __name__ == "__main__":
    raise SystemExit(main())
