#!/usr/bin/env python3
"""SCADA log forwarder for FUXA runtime logs.

Tail one or more FUXA log files, classify interesting lines, and forward
normalized JSON events to the OT Collector over UDP or TCP.

Environment variables:
  SCADA_LOG_PATHS              Colon-separated log paths to tail.
  SCADA_ASSET_IP               Asset IP recorded in emitted events.
  SCADA_ASSET_NAME             Asset name recorded in emitted events.
  SCADA_OT_COLLECTOR_HOST      Collector host (default: 192.168.1.70).
  SCADA_OT_COLLECTOR_PORT      Collector port (default: 514).
  SCADA_OT_COLLECTOR_PROTO     udp|tcp (default: udp).
  SCADA_FORWARDER_DEBUG        true/false. Log every line read.
  SCADA_DISABLE_DEDUP          true/false. Disable event deduplication.
  SCADA_TAIL_FROM_END          true/false. Default true in production.
  SCADA_DEDUP_WINDOW_SECONDS   Dedup window in seconds (default: 30).

Validation:
  python3 scada_log_forwarder.py --validate-fixtures
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import queue
import re
import socket
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


FUXA_LINE_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s+\[(?P<level>\w+)\]\s+(?P<body>.*)$")
CONNECTION_ATTEMPT_RE = re.compile(
    r'(?i)^(?:"(?P<q1>[^"]+)"|\'(?P<q2>[^\']+)\'|(?P<bare>.+?))\s+try\s+to\s+connect(?:\s+to)?\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})$'
)
CONNECTION_ATTEMPT_ERROR_RE = re.compile(
    r'(?i)^(?:"(?P<q1>[^"]+)"|\'(?P<q2>[^\']+)\'|(?P<bare>.+?))\s+try\s+to\s+connect\s+error!$'
)
CONNECTION_ERROR_GENERIC_RE = re.compile(r"(?i)^connect error!$")
CONNECTED_RE = re.compile(
    r'(?i)^(?:"(?P<q1>[^"]+)"|\'(?P<q2>[^\']+)\'|(?P<bare>.+?))\s+connected!$'
)


@dataclasses.dataclass
class Classification:
    message: str
    event_category: str
    severity: str
    target: Optional[str] = None
    target_ip: Optional[str] = None
    risk_level: str = "LOW"
    raw_level: Optional[str] = None


@dataclasses.dataclass
class TailState:
    path: Path
    fh: Optional[object] = None
    inode: Optional[int] = None
    position: int = 0
    initialized: bool = False


class Deduper:
    def __init__(self, window_seconds: int = 30) -> None:
        self.window_seconds = window_seconds
        self.seen: Dict[str, float] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        self._prune(now)
        last = self.seen.get(key)
        if last is not None and now - last < self.window_seconds:
            return False
        self.seen[key] = now
        return True

    def _prune(self, now: float) -> None:
        expired = [k for k, v in self.seen.items() if now - v >= self.window_seconds]
        for key in expired:
            self.seen.pop(key, None)


class Forwarder:
    def __init__(self) -> None:
        self.paths = [Path(p) for p in os.getenv("SCADA_LOG_PATHS", "/usr/src/app/FUXA/server/_logs/fuxa.log").split(":") if p.strip()]
        self.asset_ip = os.getenv("SCADA_ASSET_IP", "192.168.1.60")
        self.asset_name = os.getenv("SCADA_ASSET_NAME", "FUXA SCADA")
        self.collector_host = os.getenv("SCADA_OT_COLLECTOR_HOST", "192.168.1.70")
        self.collector_port = int(os.getenv("SCADA_OT_COLLECTOR_PORT", "514"))
        self.collector_proto = os.getenv("SCADA_OT_COLLECTOR_PROTO", "udp").strip().lower()
        self.debug = is_true(os.getenv("SCADA_FORWARDER_DEBUG", "false"))
        self.disable_dedup = is_true(os.getenv("SCADA_DISABLE_DEDUP", "false"))
        self.tail_from_end = is_true(os.getenv("SCADA_TAIL_FROM_END", "true"))
        self.dedup = Deduper(int(os.getenv("SCADA_DEDUP_WINDOW_SECONDS", "30")))
        self.states = [TailState(path=p) for p in self.paths]

    def run(self) -> None:
        if not self.paths:
            log("no log paths configured")
            return

        while True:
            progressed = False
            for state in self.states:
                if self._open_if_needed(state):
                    progressed = True
                if state.fh is None:
                    continue
                progressed |= self._drain_available(state)
            if not progressed:
                time.sleep(0.25)

    def _open_if_needed(self, state: TailState) -> bool:
        try:
            st = state.path.stat()
        except FileNotFoundError:
            self._close_state(state)
            return False
        except OSError as exc:
            log(f"forwarder path_error path={state.path} error={exc}")
            self._close_state(state)
            return False

        inode = getattr(st, "st_ino", None)
        needs_open = state.fh is None or not state.initialized or state.inode != inode or self._is_truncated(state, st)
        if not needs_open:
            return False

        self._close_state(state)
        try:
            state.fh = state.path.open("r", encoding="utf-8", errors="replace")
            state.inode = inode
            if self.tail_from_end and not state.initialized:
                state.fh.seek(0, os.SEEK_END)
            else:
                state.fh.seek(0, os.SEEK_SET)
            state.position = state.fh.tell()
            state.initialized = True
            log(f"forwarder opened path={state.path} tail_from_end={self.tail_from_end}")
            return True
        except FileNotFoundError:
            self._close_state(state)
            return False
        except OSError as exc:
            log(f"forwarder open_failed path={state.path} error={exc}")
            self._close_state(state)
            return False

    def _is_truncated(self, state: TailState, st: os.stat_result) -> bool:
        try:
            return state.fh is not None and st.st_size < state.position
        except Exception:
            return False

    def _close_state(self, state: TailState) -> None:
        if state.fh is not None:
            try:
                state.fh.close()
            except Exception:
                pass
        state.fh = None
        state.inode = None
        state.position = 0

    def _drain_available(self, state: TailState) -> bool:
        progressed = False
        while True:
            try:
                line = state.fh.readline()
            except OSError as exc:
                log(f"forwarder read_error path={state.path} error={exc}")
                self._close_state(state)
                return True
            if not line:
                break
            progressed = True
            state.position = state.fh.tell()
            line = line.rstrip("\r\n")
            if not line:
                continue
            if self.debug:
                log(f"read line={line}")
            classification = classify_line(line)
            if classification is None:
                continue
            if not self.disable_dedup and not self.dedup.allow(dedup_key(classification, line)):
                if self.debug:
                    log(f"dedup_skip message={classification.message} target={classification.target or ''} target_ip={classification.target_ip or ''}")
                continue
            event = build_event(classification, line, self.asset_name, self.asset_ip)
            if self._emit_event(event):
                log(
                    "forwarded "
                    f"message={event['message']} "
                    f"target={event['raw'].get('target', '')} "
                    f"target_ip={event['raw'].get('target_ip', '')}"
                )
        return progressed

    def _emit_event(self, event: Dict[str, object]) -> bool:
        payload = (json.dumps(event, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
        try:
            if self.collector_proto == "tcp":
                with socket.create_connection((self.collector_host, self.collector_port), timeout=3.0) as sock:
                    sock.sendall(payload)
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(payload, (self.collector_host, self.collector_port))
            return True
        except OSError as exc:
            log(f"forward_failed error={exc}")
            return False


def is_true(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def log(message: str) -> None:
    print(message, flush=True)


def _clean_body(line: str) -> Tuple[str, Optional[str]]:
    match = FUXA_LINE_RE.match(line)
    if match:
        return match.group("body").strip(), match.group("level").strip().lower()
    return line.strip(), None


def _unwrap_target(match: re.Match[str]) -> str:
    for group in ("q1", "q2", "bare"):
        value = match.group(group)
        if value:
            return value.strip().strip("\"'")
    return ""


def classify_line(line: str) -> Optional[Classification]:
    body, level = _clean_body(line)
    lower = body.lower()

    match = CONNECTION_ATTEMPT_ERROR_RE.match(body)
    if match:
        target = _unwrap_target(match)
        severity = "warning" if target else "error"
        return Classification(
            message="scada_plc_connection_error",
            event_category="data_collection",
            severity=severity,
            target=target or None,
            risk_level="MEDIUM",
            raw_level=level,
        )

    if CONNECTION_ERROR_GENERIC_RE.match(body):
        return Classification(
            message="scada_plc_connection_error",
            event_category="data_collection",
            severity="error",
            risk_level="MEDIUM",
            raw_level=level,
        )

    match = CONNECTION_ATTEMPT_RE.match(body)
    if match:
        target = _unwrap_target(match)
        return Classification(
            message="scada_plc_connection_attempt",
            event_category="data_collection",
            severity="info",
            target=target or None,
            target_ip=match.group("ip"),
            risk_level="LOW",
            raw_level=level,
        )

    match = CONNECTED_RE.match(body)
    if match:
        target = _unwrap_target(match)
        return Classification(
            message="scada_plc_connected",
            event_category="data_collection",
            severity="info",
            target=target or None,
            risk_level="LOW",
            raw_level=level,
        )

    return None


def dedup_key(classification: Classification, line: str) -> str:
    return "|".join([
        classification.message,
        classification.event_category,
        classification.target or "",
        classification.target_ip or "",
        line,
    ])


def build_event(classification: Classification, line: str, asset_name: str, asset_ip: str) -> Dict[str, object]:
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    raw: Dict[str, object] = {
        "line": line,
    }
    if classification.target is not None:
        raw["target"] = classification.target
    if classification.target_ip is not None:
        raw["target_ip"] = classification.target_ip

    tags: Dict[str, object] = {
        "risk_level": classification.risk_level,
        "normalized": True,
        "normalization_source": "scada_log_forwarder",
    }

    event: Dict[str, object] = {
        "timestamp": now,
        "received_at": now,
        "zone": "OT",
        "source_type": "scada",
        "asset_name": asset_name,
        "asset_ip": asset_ip,
        "severity": classification.severity,
        "protocol": "scada_runtime",
        "event_category": classification.event_category,
        "message": classification.message,
        "raw": raw,
        "tags": tags,
    }
    return event


def validate_fixtures(fixtures_path: Path) -> int:
    with fixtures_path.open("r", encoding="utf-8") as fh:
        cases = json.load(fh)

    failures = 0
    for case in cases:
        line = case["line"]
        want = case["expect"]
        got = classify_line(line)
        if got is None:
            print(f"FAIL {case['name']}: no classification", file=sys.stderr)
            failures += 1
            continue
        checks = {
            "message": got.message,
            "event_category": got.event_category,
            "severity": got.severity,
            "target": got.target,
            "target_ip": got.target_ip,
            "risk_level": got.risk_level,
        }
        for key, expected in want.items():
            if checks.get(key) != expected:
                print(
                    f"FAIL {case['name']}: {key} expected={expected!r} got={checks.get(key)!r}",
                    file=sys.stderr,
                )
                failures += 1
                break
        else:
            print(f"PASS {case['name']}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--validate-fixtures", action="store_true")
    parser.add_argument(
        "--fixtures",
        default=str(Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "scada_forwarder_cases.json"),
    )
    args = parser.parse_args()

    if args.validate_fixtures:
        return 1 if validate_fixtures(Path(args.fixtures)) else 0

    forwarder = Forwarder()
    try:
        forwarder.run()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
