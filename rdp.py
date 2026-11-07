#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fleet_ping.py - RDP CHECKER - MADE IN DHTOOLS - FROM #

Input file (a.txt), one server per line:
    ip:user:pass

Output file:
    banner.txt

Usage:
    python3 fleet_ping.py
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime

# ------------------------------- configuration -------------------------------

INPUT_FILE = "a.txt"
BANNER_FILE = "banner.txt"

COMMANDS = ["echo slm"]
WORKERS = 20
RACERS_PER_IP = 2

PORT_PROBE_TIMEOUT = 1.5
WINRM_TIMEOUT = (8, 15)
RDP_CONNECT_WAIT = 12
RDP_SETTLE = 2.5
RDP_OUTPUT_WAIT = 15
RACE_BUDGET = 60
SCREEN = (800, 600)
CHAR_SLEEP = 0.006

XFRDP_CANDIDATES = ("xfreerdp", "xfreerdp3", "xfreerdp2")

PRINT_LOCK = threading.Lock()

HEADER_TITLE = "RDP CHECKER  -  MADE IN DHTOOLS  -  FROM #"
BANNER_TITLE = "RDP CHECK"
WIDTH = 78

# ------------------------------- helpers -------------------------------


def safe_print(msg: str) -> None:
    with PRINT_LOCK:
        try:
            print(msg, flush=True)
        except UnicodeEncodeError:
            print(msg.encode("utf-8", "replace").decode("ascii", "replace"), flush=True)


def decode(b: bytes) -> str:
    for enc in ("utf-8", "cp866", "cp1251"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            continue
    return b.decode("latin-1", "replace")


def mask(text: str, secret: str) -> str:
    if secret and secret in text:
        text = text.replace(secret, "********")
    return text


def public_reason(err: str, password: str = "") -> str:
    """Collapse backend error text to a generic public reason. No method names."""
    t = mask(err or "", password).lower()
    if "cancel" in t:
        return "timeout"
    if "winrm" in t or "wsman" in t or "rdp" in t or "tsclient" in t or "xvfb" in t or "xfreerdp" in t or "pywinrm" in t:
        return "connection failed"
    if "port" in t and ("closed" in t or "refus" in t):
        return "connection refused"
    if "aborted" in t or "reset" in t or "refused" in t:
        return "connection failed"
    if "timed out" in t or "timeout" in t:
        return "timeout"
    if "not installed" in t or "unavailable" in t or "missing" in t:
        return "unavailable"
    return "connection failed"


def port_open(host: str, port: int, timeout: float = PORT_PROBE_TIMEOUT) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_ports(host: str, ports: list[int], timeout: float = PORT_PROBE_TIMEOUT) -> dict[int, bool]:
    results: dict[int, bool] = {}
    lock = threading.Lock()

    def check(p: int) -> None:
        ok = port_open(host, p, timeout)
        with lock:
            results[p] = ok

    threads = [threading.Thread(target=check, args=(p,), daemon=True) for p in ports]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 1)
    return results


def human(seconds: float) -> str:
    return f"{seconds:.2f}s" if seconds < 60 else f"{seconds / 60:.1f}m"


def _wait(cancel: threading.Event, secs: float) -> None:
    if cancel.wait(secs):
        raise RuntimeError("cancelled by race")


def indent_block(text: str, prefix: str = "          ") -> list[str]:
    text = text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
    if not text.strip():
        return [prefix + "<empty output>"]
    return [prefix + line for line in text.split("\n")]


# ------------------------------- skin -------------------------------


def frame(title: str, body: list[str], width: int = WIDTH) -> list[str]:
    inner = width - 2
    label = f"  [ {title} ]  " if title else ""
    top = "#" + "=" * 2 + label + "=" * (inner - 2 - len(label)) + "#"
    out = [top]
    for line in body:
        padded = line[:inner].ljust(inner)
        out.append("|" + padded + "|")
    out.append("#" + "=" * inner + "#")
    return out


def rule(width: int = WIDTH, ch: str = "-") -> str:
    return "|" + ch * (width - 2) + "|"


def kv(label: str, value: str, label_w: int = 16, width: int = WIDTH) -> str:
    inner = width - 2
    line = f"  {label:<{label_w}}  {value}"
    return line[:inner].ljust(inner)


# ------------------------------- data -------------------------------


@dataclass
class Target:
    idx: int
    host: str
    user: str
    password: str
    raw: str = ""


@dataclass
class CmdResult:
    command: str
    rc: int | None
    stdout: str
    stderr: str = ""


@dataclass
class ServerResult:
    target: Target
    status: str = "FAIL"
    duration: float = 0.0
    hostname: str = ""
    commands: list[CmdResult] = field(default_factory=list)
    error: str = ""

    def render(self) -> str:
        t = self.target
        status_tag = {"OK": "OK", "PARTIAL": "PART", "FAIL": "FAIL"}.get(self.status, self.status)
        body = [
            kv("target", f"{t.host}"),
            kv("user", f"{t.user}"),
            kv("status", f"{status_tag}   time: {human(self.duration)}"),
        ]
        if self.hostname:
            body.append(kv("hostname", self.hostname))
        if self.error:
            body.append(kv("error", self.error))
        for c in self.commands:
            rc = "?" if c.rc is None else c.rc
            body.append(rule())
            body.append(f"  $ {c.command}    [rc={rc}]")
            if c.stdout.strip():
                body.extend(indent_block(c.stdout))
            if c.stderr.strip():
                body.append("          stderr:")
                body.extend(indent_block(c.stderr, "            "))
        return "\n".join(frame(f"{t.idx:02d} | {t.host}", body)) + "\n"


# ------------------------------- WinRM backend -------------------------------


class WinRMBackend:
    @staticmethod
    def import_ok() -> bool:
        try:
            import winrm.protocol  # noqa: F401
            return True
        except Exception:
            return False

    def pick_endpoint(self, host: str) -> tuple[str, int] | None:
        ports = probe_ports(host, [5986, 5985])
        if ports.get(5986):
            return "https", 5986
        if ports.get(5985):
            return "http", 5985
        return None

    def _exec(self, proto, shell_id: str, command: str) -> CmdResult:
        cid = proto.run_command(shell_id, "cmd.exe", ["/c", command])
        try:
            out, err, rc = proto.get_command_output(shell_id, cid)
        finally:
            proto.cleanup_command(shell_id, cid)
        return CmdResult(command, int(rc), decode(out), decode(err))

    def run(self, target: Target, commands: list[str], cancel: threading.Event):
        if not self.import_ok():
            raise RuntimeError("backend unavailable")
        from winrm.protocol import Protocol

        ep = self.pick_endpoint(target.host)
        if ep is None:
            raise RuntimeError("port closed")
        scheme, port = ep

        proto = Protocol(
            endpoint=f"{scheme}://{target.host}:{port}/wsman",
            transport="ntlm",
            username=target.user,
            password=target.password,
            server_cert_validation="ignore",
            operation_timeout_sec=WINRM_TIMEOUT[0],
            read_timeout_sec=WINRM_TIMEOUT[1],
        )

        shell_id = proto.open_shell()
        try:
            host = self._exec(proto, shell_id, "hostname")
            results: list[CmdResult] = []
            for c in commands:
                if cancel.is_set():
                    break
                results.append(self._exec(proto, shell_id, c))
        finally:
            try:
                proto.close_shell(shell_id)
            except Exception:
                pass

        return host.stdout.strip(), results


# ------------------------------- RDP backend -------------------------------


class XInput:
    def __init__(self, display_name: str):
        from Xlib import display  # noqa: F401

        self.d = display.Display(display_name)

    def find_window(self, needle: str, timeout: float, cancel: threading.Event | None = None):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if cancel is not None and cancel.is_set():
                raise RuntimeError("cancelled by race")
            root = self.d.screen().root
            for w in root.query_tree().children:
                try:
                    name = w.get_wm_name()
                except Exception:
                    name = None
                if name and needle in str(name):
                    return w
            time.sleep(0.4)
        return None

    def focus(self, win) -> None:
        from Xlib import X

        self.d.set_input_focus(win, X.RevertToParent, X.CurrentTime)
        self.d.sync()

    def _keymap(self) -> dict[int, tuple[int, bool]]:
        cached = getattr(self, "_km", None)
        if cached is not None:
            return cached
        km: dict[int, tuple[int, bool]] = {}
        first = self.d.display.info.min_keycode
        count = self.d.display.info.max_keycode - first + 1
        mapping = self.d.get_keyboard_mapping(first, count)
        for i, syms in enumerate(mapping):
            kc = first + i
            for level, sym in enumerate(syms[:2]):
                if sym and sym not in km:
                    km[sym] = (kc, level == 1)
        self._km = km
        return km

    def type_text(self, text: str) -> None:
        from Xlib import X, XK

        km = self._keymap()
        shift_kc = self.d.keysym_to_keycode(XK.string_to_keysym("Shift_L"))
        names = {
            " ": "space", "\t": "Tab", "\n": "Return", "\\": "backslash",
            "-": "minus", ".": "period", "/": "slash", ":": "colon",
            '"': "quotedbl", "%": "percent", "_": "underscore",
            ">": "greater", "<": "less", "|": "bar", "^": "asciicircum",
            "&": "ampersand", "(": "parenleft", ")": "parenright",
            "=": "equal", "@": "at", "#": "numbersign", "$": "dollar",
            ";": "semicolon", "'": "apostrophe", ",": "comma",
            "{": "braceleft", "}": "braceright", "~": "asciitilde",
            "!": "exclam", "*": "asterisk", "+": "plus", "?": "question",
        }
        for ch in text:
            sym = XK.string_to_keysym(names.get(ch, ch))
            kc, shift = km.get(sym, (None, False))
            if not kc:
                raise RuntimeError(f"char not in keymap: {ch!r}")
            if shift:
                self.xtest_fake(X.KeyPress, shift_kc)
            self.xtest_fake(X.KeyPress, kc)
            self.xtest_fake(X.KeyRelease, kc)
            if shift:
                self.xtest_fake(X.KeyRelease, shift_kc)
            self.d.sync()
            time.sleep(CHAR_SLEEP)

    def xtest_fake(self, kind, kc) -> None:
        from Xlib.ext import xtest

        xtest.fake_input(self.d, kind, kc)

    def key_combo(self, *keysyms: str) -> None:
        from Xlib import X, XK

        codes = [self.d.keysym_to_keycode(XK.string_to_keysym(k)) for k in keysyms]
        for kc in codes:
            self.xtest_fake(X.KeyPress, kc)
        for kc in reversed(codes):
            self.xtest_fake(X.KeyRelease, kc)
        self.d.sync()

    def screenshot(self, path: str) -> None:
        subprocess.run(
            ["import", "-window", "root", path],
            env={**os.environ, "DISPLAY": self.d.get_display_name()},
            check=False, capture_output=True,
        )


class RDPBackend:
    @staticmethod
    def available() -> tuple[bool, str]:
        if not shutil.which("Xvfb"):
            return False, "unavailable"
        if not any(shutil.which(b) for b in XFRDP_CANDIDATES):
            return False, "unavailable"
        try:
            from Xlib import display  # noqa: F401
        except Exception:
            return False, "unavailable"
        return True, ""

    @staticmethod
    def _free_display() -> str:
        for n in range(90, 200):
            if not os.path.exists(f"/tmp/.X11-unix/X{n}") and not os.path.exists(f"/tmp/.X{n}-lock"):
                return f":{n}"
        raise RuntimeError("no display")

    def run(self, target: Target, commands: list[str], cancel: threading.Event):
        ok, why = self.available()
        if not ok:
            raise RuntimeError(why or "unavailable")
        if not port_open(target.host, 3389):
            raise RuntimeError("port closed")

        xfreerdp = next(shutil.which(b) for b in XFRDP_CANDIDATES)
        workdir = tempfile.mkdtemp(prefix="rdp_")
        share = os.path.join(workdir, "share")
        os.makedirs(share, exist_ok=True)
        disp = self._free_display()
        w, h = SCREEN

        xvfb = subprocess.Popen(
            ["Xvfb", disp, "-screen", "0", f"{w}x{h}x24", "-nolisten", "tcp"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        client = None
        log_path = os.path.join(workdir, "c.log")
        log_fh = open(log_path, "wb")
        try:
            _wait(cancel, 1.2)
            env = {**os.environ, "DISPLAY": disp}
            cmdline = [
                xfreerdp,
                f"/v:{target.host}",
                f"/u:{target.user}",
                f"/p:{target.password}",
                "/cert:ignore",
                f"/size:{w}x{h}",
                "/timeout:8000",
                f"/drive:share,{share}",
                "/log-level:ERROR",
            ]
            client = subprocess.Popen(
                cmdline, env=env, stdin=subprocess.DEVNULL,
                stdout=log_fh, stderr=log_fh,
            )

            xi = XInput(disp)
            win = xi.find_window("FreeRDP", RDP_CONNECT_WAIT, cancel)
            if win is None:
                raise RuntimeError("login failed")

            _wait(cancel, RDP_SETTLE)
            xi.focus(win)

            xi.key_combo("Super_L", "r")
            _wait(cancel, 1.5)
            xi.type_text("cmd")
            xi.key_combo("Return")
            _wait(cancel, 2.0)

            xi.type_text("hostname > \\\\tsclient\\share\\__host.txt 2>&1")
            xi.key_combo("Return")
            _wait(cancel, 0.3)

            for i, command in enumerate(commands):
                remote_path = f"\\\\tsclient\\share\\cmd{i}.txt"
                xi.type_text(f"{command} > {remote_path} 2>&1")
                xi.key_combo("Return")
                _wait(cancel, 0.3)

            xi.type_text("exit")
            xi.key_combo("Return")

            paths = [os.path.join(share, f"cmd{i}.txt") for i in range(len(commands))]
            deadline = time.time() + RDP_OUTPUT_WAIT
            while time.time() < deadline:
                if all(os.path.exists(p) and os.path.getsize(p) > 0 for p in paths):
                    break
                if cancel.is_set():
                    raise RuntimeError("cancelled by race")
                time.sleep(0.4)

            results: list[CmdResult] = []
            missing = [i for i, p in enumerate(paths) if not os.path.exists(p)]
            for i, command in enumerate(commands):
                p = paths[i]
                out = ""
                if os.path.exists(p):
                    with open(p, "rb") as fh:
                        out = decode(fh.read())
                results.append(CmdResult(command, 0 if os.path.exists(p) else None, out))

            if missing:
                raise RuntimeError("no output returned")

            hostname = ""
            hn_path = os.path.join(share, "__host.txt")
            if os.path.exists(hn_path):
                try:
                    with open(hn_path, "rb") as fh:
                        hostname = decode(fh.read()).strip().splitlines()[0].strip()
                except Exception:
                    hostname = ""

            return hostname, results
        finally:
            for proc in (client, xvfb):
                if proc and proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
            try:
                log_fh.close()
            except Exception:
                pass
            shutil.rmtree(workdir, ignore_errors=True)


# ------------------------------- banner -------------------------------


def build_banner(ordered: list[ServerResult], hide_pass: bool = False) -> str:
    marks = {"OK": "[Checked]", "PARTIAL": "[Partial]", "FAIL": "[Failed]"}
    ok = sum(1 for r in ordered if r.status == "OK")
    part = sum(1 for r in ordered if r.status == "PARTIAL")
    bad = sum(1 for r in ordered if r.status == "FAIL")
    now = datetime.now()

    lines: list[str] = []
    lines.extend(frame(BANNER_TITLE, [
        kv("checked", f"{ok}/{len(ordered)}"),
        kv("time", f"{now:%Y-%m-%d  %H:%M}"),
        kv("result", f"OK={ok}   PARTIAL={part}   FAIL={bad}"),
    ]))
    lines.append("")
    lines.append("#" + "=" * 76 + "#")
    lines.append("|  " + "RESULTS".ljust(74) + "|")
    lines.append("#" + "-" * 76 + "#")
    for r in ordered:
        pw = "******" if hide_pass else r.target.password
        line = f"  {r.target.host}:{r.target.user}:{pw}:{marks.get(r.status, '[Unknown]')}"
        lines.append("|  " + line[:74].ljust(74) + "|")
    lines.append("#" + "=" * 76 + "#")
    return "\n".join(lines) + "\n"


# ------------------------------- core -------------------------------


def parse_targets(path: str) -> tuple[list[Target], list[str]]:
    targets: list[Target] = []
    problems: list[str] = []
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            parts = raw.split(":", 2)
            if len(parts) < 3 or not parts[0] or not parts[1]:
                problems.append(f"line {lineno}: '{raw}' missing ip:user:pass")
                continue
            host, user, password = (p.strip() for p in parts)
            if not password:
                problems.append(f"line {lineno}: empty password")
                continue
            targets.append(Target(len(targets) + 1, host, user, password, raw))
    return targets, problems


def process(target: Target, commands: list[str]) -> ServerResult:
    started = time.time()
    res = ServerResult(target=target)

    cond = threading.Condition()
    state: dict = {"winner": None, "remaining": RACERS_PER_IP, "errors": [], "result": None}
    cancel = threading.Event()

    def attempt(backend) -> None:
        try:
            hostname, cmd_results = backend.run(target, commands, cancel)
            with cond:
                if state["winner"] is None:
                    state["winner"] = backend
                    state["result"] = (hostname, cmd_results)
                    cancel.set()
                state["remaining"] -= 1
                cond.notify_all()
        except Exception as exc:  # noqa: BLE001
            with cond:
                state["errors"].append(f"{type(exc).__name__}: {exc}")
                state["remaining"] -= 1
                cond.notify_all()

    threads = [
        threading.Thread(target=attempt, args=(WinRMBackend(),), daemon=True),
        threading.Thread(target=attempt, args=(RDPBackend(),), daemon=True),
    ]
    for t in threads:
        t.start()

    deadline = time.time() + RACE_BUDGET
    with cond:
        while state["winner"] is None and state["remaining"] > 0:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            cond.wait(timeout=remaining)

    for t in threads:
        t.join(timeout=3)

    res.duration = time.time() - started

    if state["winner"] is not None:
        hostname, cmd_results = state["result"]
        res.hostname = hostname
        res.commands = cmd_results
        res.status = "OK"
        if any(c.rc not in (0, None) for c in res.commands):
            res.status = "PARTIAL"
    else:
        res.status = "FAIL"
        res.error = public_reason("\n".join(state["errors"]), target.password)

    return res


def live_line(res: ServerResult, total: int) -> str:
    tag = {"OK": "[+]", "PARTIAL": "[~]", "FAIL": "[-]"}.get(res.status, "[?]")
    detail = res.hostname if res.status in ("OK", "PARTIAL") and res.hostname else ""
    if not detail and res.status == "FAIL":
        detail = res.error or "connection failed"
    idx = res.target.idx
    core = f"{tag}  [{idx:02d}/{total:02d}]  {res.target.host:<18}  {res.status:<7}  {human(res.duration):<7}  {detail}"
    return core[:76].ljust(76)


def main() -> int:
    if not os.path.exists(INPUT_FILE):
        safe_print(f"input file not found: {INPUT_FILE}")
        return 2

    targets, problems = parse_targets(INPUT_FILE)
    for p in problems:
        safe_print("warning: " + p)
    if not targets:
        safe_print("no valid servers in input file")
        return 2

    seen: set[str] = set()
    uniq: list[Target] = []
    for t in targets:
        if t.host in seen:
            safe_print(f"warning: {t.host} duplicated, skipped")
            continue
        seen.add(t.host)
        uniq.append(t)
    targets = uniq

    started = datetime.now()

    header_lines = [
        HEADER_TITLE,
        "",
        kv("started", f"{started:%Y-%m-%d  %H:%M:%S}"),
        kv("targets", f"{len(targets)}"),
        kv("racers/IP", f"{RACERS_PER_IP}"),
    ]
    header = "\n".join(frame("CONFIG", header_lines)) + "\n"
    safe_print(header)

    safe_print("#" + "=" * 76 + "#")
    safe_print("|  " + "LIVE".ljust(74) + "|")
    safe_print("#" + "-" * 76 + "#")

    results: dict[int, ServerResult] = {}
    t0 = time.time()
    total = len(targets)
    with ThreadPoolExecutor(max_workers=max(1, min(WORKERS, total))) as pool:
        futures = {pool.submit(process, t, COMMANDS): t for t in targets}
        for fut in as_completed(futures):
            t = futures[fut]
            try:
                res = fut.result()
            except Exception as exc:  # noqa: BLE001
                res = ServerResult(target=t, status="FAIL", error=public_reason(str(exc), t.password))
            results[t.idx] = res
            safe_print("|  " + live_line(res, total) + "  |")
            if res.status != "OK":
                safe_print(res.render())

    safe_print("#" + "=" * 76 + "#")
    safe_print("")

    ordered = [results[i] for i in sorted(results)]
    ok = sum(1 for r in ordered if r.status == "OK")
    part = sum(1 for r in ordered if r.status == "PARTIAL")
    bad = sum(1 for r in ordered if r.status == "FAIL")
    wall = time.time() - t0

    head_row = f"  {'#':<3} {'HOST':<20} {'STATUS':<8} {'TIME':<8} HOSTNAME"
    divider = rule()
    rows = [head_row, divider]
    for r in ordered:
        rows.append(
            f"  {r.target.idx:<3} {r.target.host:<20} {r.status:<8} "
            f"{human(r.duration):<8} {r.hostname}"
        )
    rows.append(divider)
    rows.append(
        f"  OK: {ok}    PARTIAL: {part}    FAIL: {bad}    TOTAL: {len(ordered)}    "
        f"WALL: {human(wall)}"
    )
    summary = "\n".join(frame("SUMMARY", rows)) + "\n"
    safe_print(summary)

    banner = build_banner(ordered)
    try:
        with open(BANNER_FILE, "w", encoding="utf-8") as fh:
            fh.write(banner)
        os.chmod(BANNER_FILE, 0o600)
        safe_print(banner)
        safe_print(f"banner written to: {os.path.abspath(BANNER_FILE)}")
    except Exception as exc:  # noqa: BLE001
        safe_print(f"failed to write banner: {exc}")

    return 0 if bad == 0 else 1


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
