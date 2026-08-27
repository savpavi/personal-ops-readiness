#!/usr/bin/env python3
"""Deterministic, read-only workstation readiness report."""

from __future__ import annotations

import argparse
import configparser
import datetime as dt
import glob
import json
import os
import pathlib
import platform
import re
import subprocess
import sys
from typing import Any


HOME = pathlib.Path.home()
MOUNT_CANDIDATES = [
    pathlib.Path("/"),
    HOME,
    pathlib.Path("/srv/storage"),
    pathlib.Path("/srv/disk6"),
    pathlib.Path("/srv/disk12"),
    pathlib.Path("/srv/lexar"),
]
TIMER_DIR = HOME / ".config/systemd/user"
VAULT_GIT_STATUS = HOME / "vm-setup/vault-git-backup-status.txt"
ARCHIVE_STATUS = HOME / ".local/state/archive-critical-backup/status.txt"
SMART_ALERT_LOG = pathlib.Path("/var/log/smartd-alerts.log")


def run(command: list[str], timeout: int = 15) -> subprocess.CompletedProcess[bytes]:
    env = {**os.environ, "LC_ALL": "C", "LANG": "C"}
    try:
        return subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(command, 126, b"", b"")


def classify_storage_percent(percent: int) -> str:
    if percent >= 95:
        return "RED"
    if percent >= 90:
        return "ORANGE"
    if percent >= 85:
        return "YELLOW"
    return "GREEN"


def severity_for_storage(status: str) -> str:
    return {"RED": "CRITICAL", "ORANGE": "WARNING", "YELLOW": "WARNING"}.get(
        status, "INFO"
    )


def capacity_guidance(percent: int) -> dict[str, Any]:
    status = classify_storage_percent(percent)
    return {
        "status": status,
        "severity": severity_for_storage(status),
        "headroom_to_red_points": max(0, 95 - percent),
        "recommendation": "CAPACITY ACTION SOON" if percent == 94 else None,
    }


def parse_git_porcelain(raw: bytes) -> dict[str, int]:
    entries = raw.split(b"\0")
    result = {"modified": 0, "deleted": 0, "untracked": 0}
    skip_path = False
    for entry in entries:
        if not entry:
            continue
        if skip_path:
            skip_path = False
            continue
        status = entry[:2].decode("ascii", "replace")
        if status == "??":
            result["untracked"] += 1
        elif "D" in status:
            result["deleted"] += 1
        else:
            result["modified"] += 1
        if "R" in status or "C" in status:
            skip_path = True
    return result


def parse_smartctl(payload: dict[str, Any]) -> dict[str, Any]:
    smartctl = payload.get("smartctl", {})
    exit_status = int(smartctl.get("exit_status", 0) or 0)
    passed = payload.get("smart_status", {}).get("passed")
    temperature = payload.get("temperature", {}).get("current")
    nvme = payload.get("nvme_smart_health_information_log", {})
    critical_warning = int(nvme.get("critical_warning", 0) or 0)
    media_errors = int(nvme.get("media_errors", 0) or 0)
    warnings: list[str] = []
    severity = "INFO"

    collection_failed = bool(exit_status & 0b111) and passed is None and not nvme
    if collection_failed:
        return {
            "health": "UNKNOWN",
            "temperature_c": None,
            "critical_warning": None,
            "media_errors": None,
            "severity": "UNKNOWN",
            "warnings": ["SMART data could not be collected"],
        }

    health = "PASSED" if passed is True else "FAILED" if passed is False else "UNKNOWN"
    if passed is False or critical_warning or exit_status & (8 | 16):
        severity = "CRITICAL"
        warnings.append("SMART reports a current critical health condition")
    if media_errors:
        severity = "WARNING" if severity != "CRITICAL" else severity
        warnings.append(f"NVMe reports {media_errors} media/data integrity errors")
    if isinstance(temperature, (int, float)) and temperature >= 70:
        severity = "WARNING" if severity != "CRITICAL" else severity
        warnings.append(f"Current temperature is elevated at {temperature:g} C")
    if exit_status & (32 | 64 | 128):
        severity = "WARNING" if severity != "CRITICAL" else severity
        warnings.append("SMART history or self-test log contains notable entries")

    return {
        "health": health,
        "temperature_c": temperature,
        "critical_warning": critical_warning,
        "media_errors": media_errors,
        "severity": severity,
        "warnings": warnings,
    }


def parse_backup_status(text: str) -> dict[str, Any]:
    match = re.fullmatch(
        r"(SUCCESS|FAILED)(?: exit=(\d+))?(?: stage=([a-z0-9-]+))? "
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})\s*",
        text,
    )
    if not match:
        return {"status": "UNKNOWN", "last_result": "UNKNOWN", "last_success": None}
    result, exit_code, stage, timestamp = match.groups()
    parsed_time = dt.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S %z")
    return {
        "status": "OK" if result == "SUCCESS" else "WARNING",
        "last_result": result,
        "last_success": parsed_time.isoformat() if result == "SUCCESS" else None,
        "last_evidence": parsed_time.isoformat(),
        "exit_code": int(exit_code) if exit_code else 0,
        "stage": stage,
    }


def parse_systemd_show(text: str) -> dict[str, str]:
    return {
        key: value
        for line in text.splitlines()
        if "=" in line
        for key, value in [line.split("=", 1)]
    }


def _systemd_timestamp(value: str | None) -> str | None:
    if not value or value == "n/a":
        return None
    cleaned = re.sub(r"^[A-Z][a-z]{2} ", "", value)
    cleaned = re.sub(r" ([+-]\d{2})$", r"\1:00", cleaned)
    try:
        return dt.datetime.fromisoformat(cleaned).isoformat()
    except ValueError:
        return value


def classify_systemd_service(evidence: dict[str, str]) -> dict[str, Any]:
    active = evidence.get("ActiveState", "UNKNOWN")
    substate = evidence.get("SubState", "UNKNOWN")
    result = evidence.get("Result") or "UNKNOWN"
    code = evidence.get("ExecMainCode") or "UNKNOWN"
    try:
        exit_status = int(evidence["ExecMainStatus"])
    except (KeyError, ValueError):
        exit_status = None
    started = _systemd_timestamp(evidence.get("ExecMainStartTimestamp"))
    completed = _systemd_timestamp(evidence.get("ExecMainExitTimestamp"))

    if active in {"active", "activating", "reloading"}:
        state = "RUNNING"
    elif result == "success" and code in {"exited", "1", "UNKNOWN"} and exit_status in {0, None} and completed:
        state = "SUCCESS"
    elif result not in {"success", "UNKNOWN", ""} or active == "failed" or (
        exit_status not in {0, None}
    ):
        state = "FAILED"
    else:
        state = "UNKNOWN"
    return {
        "state": state,
        "active_state": active,
        "sub_state": substate,
        "result": result,
        "exec_main_code": code,
        "exit_status": exit_status,
        "started": started,
        "completed": completed,
        "invocation_id": evidence.get("InvocationID") or None,
        "evidence_source": "systemd service runtime",
    }


def reconcile_backup_evidence(
    service: dict[str, Any], stamp: dict[str, Any] | None
) -> dict[str, Any]:
    stamp = stamp or {"last_result": "UNKNOWN", "last_evidence": None}
    service_state = service.get("state", "UNKNOWN")
    stamp_result = stamp.get("last_result", "UNKNOWN")
    disagreement = False
    reason = None
    status = service_state
    service_started = service.get("started")
    stamp_time = stamp.get("last_evidence")
    newer_incomplete_invocation = False
    if service_started and stamp_time and service_state in {"UNKNOWN", "RUNNING"}:
        try:
            newer_incomplete_invocation = dt.datetime.fromisoformat(
                service_started
            ) > dt.datetime.fromisoformat(stamp_time)
        except ValueError:
            newer_incomplete_invocation = False

    if newer_incomplete_invocation:
        status = "RUNNING" if service_state == "RUNNING" else "WARNING"
        reason = "stale status artifact; newer invocation has no completion result"
    elif service_state == "SUCCESS" and stamp_result == "FAILED":
        disagreement = True
        status = "WARNING"
        reason = "stale status artifact / evidence disagreement"
    elif service_state == "FAILED":
        status = "FAILED"
    elif service_state == "SUCCESS":
        status = "SUCCESS"
    elif service_state == "RUNNING":
        status = "RUNNING"
        if stamp_result == "FAILED":
            reason = "current invocation is running; status file records an older failure"
    elif stamp_result == "FAILED":
        status = "FAILED"
        reason = "failure is recorded only by the local status artifact"
    elif stamp_result == "SUCCESS":
        status = "SUCCESS"
        reason = "success is recorded only by the local status artifact"
    else:
        status = "UNKNOWN"
    return {
        "status": status,
        "evidence_disagreement": disagreement,
        "reason": reason,
    }


def merge_smart_evidence(
    live: dict[str, Any],
    os_state: dict[str, Any] | None,
    historical_alerts: list[dict[str, str]],
) -> dict[str, Any]:
    os_state = os_state or {}
    temperature = live.get("temperature_c")
    source = "smartctl live" if temperature is not None or live.get("health") != "UNKNOWN" else None
    if temperature is None and os_state.get("temperature_c") is not None:
        temperature = os_state["temperature_c"]
        source = "sysfs hwmon"
    severity = live.get("severity", "UNKNOWN")
    warnings = list(live.get("warnings", []))
    if temperature is not None and temperature >= 70 and severity != "CRITICAL":
        severity = "WARNING"
        warning = f"Current temperature is elevated at {temperature:g} C"
        if warning not in warnings:
            warnings.append(warning)
    return {
        **live,
        "temperature_c": temperature,
        "current_health": live.get("health", "UNKNOWN"),
        "current_temperature_c": temperature,
        "os_device_state": os_state.get("state"),
        "current_evidence_source": source or ("sysfs device state" if os_state.get("state") else "none"),
        "historical_alerts": historical_alerts,
        "severity": severity,
        "warnings": warnings,
    }


def parse_timer_definition(text: str) -> dict[str, Any]:
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    try:
        parser.read_string(text)
        timer = parser["Timer"]
    except (configparser.Error, KeyError):
        return {"cadence": "unknown", "persistent": False}
    if timer.get("OnCalendar"):
        cadence = timer["OnCalendar"]
    elif timer.get("OnUnitActiveSec"):
        cadence = f"every {timer['OnUnitActiveSec']}"
    else:
        cadence = "unknown"
    return {
        "cadence": cadence,
        "persistent": timer.getboolean("Persistent", fallback=False),
    }


def overall_status(severities: list[str]) -> str:
    if "CRITICAL" in severities:
        return "RED"
    if "WARNING" in severities:
        return "YELLOW"
    if "UNKNOWN" in severities:
        return "UNKNOWN"
    return "GREEN"


def human_bytes(value: int | None) -> str:
    if value is None:
        return "UNKNOWN"
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(amount) < 1024 or unit == "PiB":
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} PiB"


def age_text(timestamp: str | None, now: dt.datetime) -> str:
    if not timestamp:
        return "UNKNOWN"
    value = dt.datetime.fromisoformat(timestamp)
    if value.tzinfo is None:
        value = value.replace(tzinfo=now.tzinfo)
    seconds = max(0, int((now - value.astimezone(now.tzinfo)).total_seconds()))
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def collect_storage() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen_targets: set[str] = set()
    for path in MOUNT_CANDIDATES:
        if not path.exists():
            continue
        mount_result = run(["findmnt", "-J", "-T", str(path), "-o", "TARGET,SOURCE,FSTYPE"])
        df_result = run(["df", "-P", "-B1", str(path)])
        if mount_result.returncode or df_result.returncode:
            continue
        try:
            filesystem = json.loads(mount_result.stdout)["filesystems"][0]
            fields = df_result.stdout.decode("utf-8", "replace").splitlines()[-1].split()
            size, used, free = map(int, fields[1:4])
            percent = int(fields[4].rstrip("%"))
        except (ValueError, KeyError, IndexError, json.JSONDecodeError):
            continue
        target = filesystem["target"]
        if target in seen_targets:
            continue
        seen_targets.add(target)
        guidance = capacity_guidance(percent)
        records.append(
            {
                "mount": target,
                "source": filesystem.get("source", "UNKNOWN"),
                "filesystem": filesystem.get("fstype", "UNKNOWN"),
                "size_bytes": size,
                "used_bytes": used,
                "free_bytes": free,
                "used_percent": percent,
                "threshold_status": guidance["status"],
                "severity": guidance["severity"],
                "headroom_to_red_points": guidance["headroom_to_red_points"],
                "recommendation": guidance["recommendation"],
            }
        )
    return records


def _sysfs_model(device_name: str) -> tuple[str | None, str | None]:
    if not device_name.startswith("nvme"):
        return None, None
    controller = re.match(r"(nvme\d+)", device_name)
    if not controller:
        return None, None
    base = pathlib.Path("/sys/class/nvme") / controller.group(1)
    try:
        model = (base / "model").read_text().strip()
        state = (base / "state").read_text().strip()
        return model, state
    except OSError:
        return None, None


def _sysfs_nvme_temperature(device_name: str) -> float | None:
    controller = re.match(r"(nvme\d+)", device_name)
    if not controller:
        return None
    for hwmon in pathlib.Path("/sys/class/hwmon").glob("hwmon*"):
        try:
            target = (hwmon / "device").resolve()
            if target.name != controller.group(1):
                continue
            return int((hwmon / "temp1_input").read_text().strip()) / 1000
        except (OSError, ValueError):
            continue
    return None


def recent_smart_alerts() -> list[dict[str, str]]:
    try:
        lines = SMART_ALERT_LOG.read_text(errors="replace").splitlines()[-50:]
    except OSError:
        return []
    alerts = []
    for line in lines:
        timestamp = line.split(" ", 1)[0] if " " in line else "UNKNOWN"
        device = re.search(r"device=([^ ]+)", line)
        alert_type = re.search(r"type=([^ ]+)", line)
        temperature = re.search(r"Temperature (\d+) Celsius", line)
        alerts.append(
            {
                "timestamp": timestamp,
                "device": device.group(1) if device else "unknown",
                "type": alert_type.group(1) if alert_type else "SMART",
                "temperature_c": temperature.group(1) if temperature else "",
            }
        )
    return alerts


def should_monitor_block_device(block: dict[str, Any]) -> bool:
    name = str(block.get("name", ""))
    return block.get("type") == "disk" and not name.startswith(("zram", "ram", "loop"))


def collect_smart() -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    result = run(["lsblk", "-J", "-d", "-o", "NAME,TYPE,MODEL"])
    devices: list[dict[str, Any]] = []
    if result.returncode == 0:
        try:
            blocks = json.loads(result.stdout).get("blockdevices", [])
        except json.JSONDecodeError:
            blocks = []
        history = recent_smart_alerts()
        for block in blocks:
            if not should_monitor_block_device(block):
                continue
            name = block.get("name", "unknown")
            command = run(["smartctl", "-j", "-a", f"/dev/{name}"], timeout=20)
            try:
                payload = json.loads(command.stdout)
            except json.JSONDecodeError:
                payload = {"smartctl": {"exit_status": 2}}
            parsed = parse_smartctl(payload)
            sysfs_model, state = _sysfs_model(name)
            device_path = f"/dev/{name}"
            device_alerts = [
                alert for alert in history if alert["device"] in {device_path, "unknown"}
            ]
            parsed = merge_smart_evidence(
                parsed,
                {"state": state, "temperature_c": _sysfs_nvme_temperature(name)},
                device_alerts,
            )
            devices.append(
                {
                    "device": device_path,
                    "model": (block.get("model") or sysfs_model or "UNKNOWN").strip(),
                    "state": state,
                    **parsed,
                }
            )
    return devices, recent_smart_alerts()


def _timer_enabled(name: str) -> bool:
    link = TIMER_DIR / "timers.target.wants" / name
    return link.is_symlink()


def collect_timer_runtime(names: list[str]) -> tuple[dict[str, dict[str, str]], str | None]:
    if not names:
        return {}, None
    result = run(
        [
            "systemctl",
            "--user",
            "show",
            *names,
            "--property=Id,LoadState,ActiveState,UnitFileState,NextElapseUSecRealtime,LastTriggerUSec",
        ]
    )
    if result.returncode:
        return {}, "user systemd bus unavailable"
    records: dict[str, dict[str, str]] = {}
    current: dict[str, str] = {}
    for line in result.stdout.decode("utf-8", "replace").splitlines() + [""]:
        if not line:
            if current.get("Id"):
                records[current["Id"]] = current
            current = {}
        elif "=" in line:
            key, value = line.split("=", 1)
            current[key] = value
    return records, None


def collect_timers() -> tuple[list[dict[str, Any]], str | None]:
    files = sorted(TIMER_DIR.glob("*.timer"))
    names = [path.name for path in files]
    runtime, reason = collect_timer_runtime(names)
    timers = []
    for path in files:
        try:
            definition = parse_timer_definition(path.read_text(errors="replace"))
        except OSError:
            definition = {"cadence": "unknown", "persistent": False}
        live = runtime.get(path.name, {})
        timers.append(
            {
                "name": path.name,
                "known": True,
                "enabled": _timer_enabled(path.name),
                "cadence": definition["cadence"],
                "persistent": definition["persistent"],
                "active_state": live.get("ActiveState", "UNKNOWN"),
                "next_run": live.get("NextElapseUSecRealtime") or None,
                "previous_run": live.get("LastTriggerUSec") or None,
                "runtime_verified": bool(live),
                "runtime_unknown_reason": reason if not live else None,
            }
        )
    return timers, reason


def _journal_service_evidence(service_name: str) -> dict[str, Any]:
    result = run(
        ["journalctl", "--user", "-u", service_name, "-n", "50", "--no-pager", "-o", "json"]
    )
    if result.returncode:
        return classify_systemd_service({})
    latest_start: tuple[int, str] | None = None
    latest_failure: tuple[int, str, int | None] | None = None
    latest_success: tuple[int, str] | None = None
    for raw_line in result.stdout.decode("utf-8", "replace").splitlines():
        try:
            entry = json.loads(raw_line)
            stamp = int(entry.get("__REALTIME_TIMESTAMP", 0))
            message = str(entry.get("MESSAGE", ""))
        except (json.JSONDecodeError, ValueError):
            continue
        timestamp = dt.datetime.fromtimestamp(stamp / 1_000_000, tz=dt.timezone.utc).astimezone().isoformat()
        if message.startswith((f"Starting {service_name}", "Starting ")):
            latest_start = (stamp, timestamp)
        status_match = re.search(r"Main process exited, code=([^,]+), status=(\d+)", message)
        if status_match and (status_match.group(1) != "exited" or int(status_match.group(2)) != 0):
            latest_failure = (stamp, timestamp, int(status_match.group(2)))
        if "Failed with result" in message or message.startswith("Failed to start"):
            exit_status = latest_failure[2] if latest_failure else None
            latest_failure = (stamp, timestamp, exit_status)
        if message.startswith(("Finished ", "Completed ")) or "Deactivated successfully" in message:
            latest_success = (stamp, timestamp)

    start_stamp = latest_start[0] if latest_start else 0
    if latest_failure and latest_failure[0] >= start_stamp:
        return {
            "state": "FAILED",
            "active_state": "UNKNOWN",
            "sub_state": "UNKNOWN",
            "result": "failure recorded in journal",
            "exec_main_code": "UNKNOWN",
            "exit_status": latest_failure[2],
            "started": latest_start[1] if latest_start else None,
            "completed": latest_failure[1],
            "invocation_id": None,
            "evidence_source": "journal completion summary",
        }
    if latest_success and latest_success[0] >= start_stamp:
        return {
            "state": "SUCCESS",
            "active_state": "inactive",
            "sub_state": "dead",
            "result": "success recorded in journal",
            "exec_main_code": "exited",
            "exit_status": 0,
            "started": latest_start[1] if latest_start else None,
            "completed": latest_success[1],
            "invocation_id": None,
            "evidence_source": "journal completion summary",
        }
    unknown = classify_systemd_service({})
    unknown.update(
        {
            "started": latest_start[1] if latest_start else None,
            "evidence_source": "journal incomplete; no completion result",
        }
    )
    return unknown


def collect_service_evidence(service_name: str) -> dict[str, Any]:
    properties = (
        "Id,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,"
        "ExecMainStartTimestamp,ExecMainExitTimestamp,InvocationID"
    )
    result = run(["systemctl", "--user", "show", service_name, f"--property={properties}"])
    if result.returncode == 0:
        return classify_systemd_service(parse_systemd_show(result.stdout.decode("utf-8", "replace")))
    return _journal_service_evidence(service_name)


def collect_backups(now: dt.datetime, timers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    backups: list[dict[str, Any]] = []
    timer_map = {timer["name"]: timer for timer in timers}
    archive_timer = TIMER_DIR / "archive-critical-backup.timer"
    if archive_timer.exists():
        definition = parse_timer_definition(archive_timer.read_text(errors="replace"))
        service = collect_service_evidence("archive-critical-backup.service")
        try:
            parsed = parse_backup_status(ARCHIVE_STATUS.read_text(errors="replace"))
        except OSError:
            parsed = {"status": "UNKNOWN", "last_result": "UNKNOWN", "last_success": None}
        reconciliation = reconcile_backup_evidence(service, parsed)
        backups.append(
            {
                "name": "archive-critical-backup",
                "expected_cadence": definition["cadence"],
                "timer_triggered": timer_map.get("archive-critical-backup.timer", {}).get("previous_run"),
                "last_result": service["state"],
                "last_success": service["completed"] if service["state"] == "SUCCESS" else None,
                "age": age_text(service.get("completed"), now),
                "destination": "/srv/lexar service prerequisite; repository location not inspected",
                "destination_available": pathlib.Path("/srv/lexar").is_mount(),
                "status": reconciliation["status"],
                "reason": reconciliation["reason"],
                "service": service,
                "status_artifact": parsed,
                "evidence_disagreement": reconciliation["evidence_disagreement"],
            }
        )
    vault_git_timer = TIMER_DIR / "vault-git-backup.timer"
    if vault_git_timer.exists():
        definition = parse_timer_definition(vault_git_timer.read_text(errors="replace"))
        try:
            parsed = parse_backup_status(VAULT_GIT_STATUS.read_text(errors="replace"))
        except OSError:
            parsed = {"status": "UNKNOWN", "last_result": "UNKNOWN", "last_success": None}
        service = collect_service_evidence("vault-git-backup.service")
        reconciliation = reconcile_backup_evidence(service, parsed)
        evidence = service.get("completed") or parsed.get("last_evidence")
        backups.append(
            {
                "name": "vault-git-backup",
                "expected_cadence": definition["cadence"],
                "timer_triggered": timer_map.get("vault-git-backup.timer", {}).get("previous_run"),
                "last_result": service["state"],
                "last_success": service["completed"] if service["state"] == "SUCCESS" else parsed.get("last_success"),
                "last_evidence": parsed.get("last_evidence"),
                "age": age_text(evidence, now),
                "destination": "/srv/lexar/Backups/obsidian-aktif-kasa.git + GitHub private mirror",
                "destination_available": pathlib.Path("/srv/lexar").is_mount(),
                "status": reconciliation["status"],
                "reason": reconciliation["reason"],
                "service": service,
                "status_artifact": parsed,
                "evidence_disagreement": reconciliation["evidence_disagreement"],
            }
        )
    return backups


def discover_repositories() -> list[pathlib.Path]:
    candidates = {
        HOME / "Projects/Ai-support-ops-copilot",
        HOME / "Projects/egebostanci-site",
        HOME / "Projects/Obsidian Web Clipper",
        HOME / "Documents/Obsidian/Aktif Kasa",
    }
    for git_dir in glob.glob(str(HOME / "Projects/*/.git")):
        candidates.add(pathlib.Path(git_dir).parent)
    return sorted(path for path in candidates if (path / ".git").is_dir())


def collect_git() -> list[dict[str, Any]]:
    repositories = []
    for path in discover_repositories():
        branch_result = run(["git", "-C", str(path), "branch", "--show-current"])
        status_result = run(["git", "-C", str(path), "status", "--porcelain=v1", "-z"])
        counts = parse_git_porcelain(status_result.stdout) if status_result.returncode == 0 else {
            "modified": 0,
            "deleted": 0,
            "untracked": 0,
        }
        upstream_result = run(
            ["git", "-C", str(path), "rev-list", "--left-right", "--count", "HEAD...@{upstream}"]
        )
        ahead = behind = None
        if upstream_result.returncode == 0:
            try:
                ahead, behind = map(int, upstream_result.stdout.split())
            except ValueError:
                ahead = behind = None
        total = sum(counts.values())
        repositories.append(
            {
                "name": path.name,
                "path": str(path),
                "branch": branch_result.stdout.decode("utf-8", "replace").strip() or "DETACHED/UNKNOWN",
                "dirty": total > 0,
                **counts,
                "upstream_available": ahead is not None,
                "ahead": ahead,
                "behind": behind,
                "large_dirty_state": total >= 20,
                "collection_ok": status_result.returncode == 0,
            }
        )
    return repositories


def build_anomalies(
    storage: list[dict[str, Any]],
    smart: list[dict[str, Any]],
    smart_alerts: list[dict[str, str]],
    backups: list[dict[str, Any]],
    timers_reason: str | None,
    repositories: list[dict[str, Any]],
) -> list[dict[str, str]]:
    anomalies: list[dict[str, str]] = []
    for item in storage:
        if item["severity"] in {"CRITICAL", "WARNING"}:
            suffix = ""
            if item["recommendation"]:
                suffix = f"; {item['recommendation']} ({item['headroom_to_red_points']} percentage point from RED)"
            anomalies.append(
                {
                    "severity": item["severity"],
                    "source": "storage",
                    "message": f"{item['mount']} is {item['used_percent']}% used ({item['threshold_status']}){suffix}",
                }
            )
    for item in smart:
        if item["severity"] in {"CRITICAL", "WARNING"}:
            for warning in item["warnings"] or ["SMART reports a notable condition"]:
                anomalies.append(
                    {"severity": item["severity"], "source": "smart", "message": f"{item['device']}: {warning}"}
                )
    for alert in smart_alerts:
        detail = f"; recorded temperature {alert['temperature_c']} C" if alert["temperature_c"] else ""
        anomalies.append(
            {
                "severity": "INFO",
                "source": "smart-history",
                "message": f"Historical SMART alert {alert['timestamp']} for {alert['device']} ({alert['type']}{detail})",
            }
        )
    for backup in backups:
        if backup["status"] == "FAILED":
            anomalies.append(
                {"severity": "WARNING", "source": "backup", "message": f"{backup['name']}: service execution failed"}
            )
        elif backup["status"] == "WARNING":
            anomalies.append(
                {"severity": "WARNING", "source": "backup", "message": f"{backup['name']}: {backup['reason']}"}
            )
        elif backup["status"] == "UNKNOWN":
            anomalies.append(
                {"severity": "UNKNOWN", "source": "backup", "message": f"{backup['name']}: success could not be verified"}
            )
    if timers_reason:
        anomalies.append(
            {"severity": "UNKNOWN", "source": "timers", "message": f"Timer runtime state unknown: {timers_reason}"}
        )
    for repo in repositories:
        if repo["large_dirty_state"]:
            total = repo["modified"] + repo["deleted"] + repo["untracked"]
            anomalies.append(
                {
                    "severity": "WARNING",
                    "source": "git",
                    "message": f"{repo['name']} has a large dirty state ({total} entries); this is not classified as corruption",
                }
            )
        elif repo["dirty"]:
            anomalies.append(
                {"severity": "INFO", "source": "git", "message": f"{repo['name']} has uncommitted changes"}
            )
        if repo["behind"]:
            anomalies.append(
                {"severity": "WARNING", "source": "git", "message": f"{repo['name']} is {repo['behind']} commit(s) behind upstream"}
            )
    priority = {
        ("backup", "WARNING"): 0,
        ("storage", "CRITICAL"): 1,
        ("storage", "WARNING"): 2,
        ("smart", "CRITICAL"): 3,
        ("smart", "WARNING"): 4,
        ("git", "WARNING"): 5,
        ("backup", "UNKNOWN"): 6,
        ("timers", "UNKNOWN"): 7,
        ("smart-history", "INFO"): 20,
    }
    return sorted(anomalies, key=lambda item: priority.get((item["source"], item["severity"]), 10))


def collect_report() -> dict[str, Any]:
    now = dt.datetime.now().astimezone()
    storage = collect_storage()
    smart, smart_alerts = collect_smart()
    timers, timer_reason = collect_timers()
    backups = collect_backups(now, timers)
    repositories = collect_git()
    anomalies = build_anomalies(
        storage, smart, smart_alerts, backups, timer_reason, repositories
    )
    essential_unknown = not storage or not smart or any(
        device["severity"] == "UNKNOWN" for device in smart
    )
    severities = [item["severity"] for item in anomalies]
    if essential_unknown:
        severities.append("UNKNOWN")
    return {
        "tool_version": "0.2",
        "schema_version": 2,
        "generated": now.isoformat(timespec="seconds"),
        "hostname": platform.node(),
        "overall_status": overall_status(severities),
        "mount_scope": [str(path) for path in MOUNT_CANDIDATES],
        "anomalies": anomalies,
        "storage": storage,
        "smart": {"devices": smart, "historical_alerts": smart_alerts},
        "backups": backups,
        "timers": timers,
        "git_repositories": repositories,
    }


def md_cell(value: Any) -> str:
    if value is None:
        return "UNKNOWN"
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Personal Operations Readiness",
        "",
        f"Generated: {report['generated']}",
        f"Hostname: {report['hostname']}",
        f"Version: {report['tool_version']}",
        "",
        "## Overall Status",
        "",
        f"**{report['overall_status']}**",
        "",
        "## Critical Alerts",
        "",
    ]
    actionable = [a for a in report["anomalies"] if a["severity"] != "INFO"]
    if actionable:
        lines.extend(f"- **{a['severity']}** [{a['source']}] {a['message']}" for a in actionable)
    else:
        lines.append("No current critical or warning conditions detected.")

    lines.extend(
        [
            "",
            "## Storage",
            "",
            "Selected scope: workstation root/home plus mounted archive paths that exist: "
            + ", ".join(f"`{p}`" for p in report["mount_scope"])
            + ". Duplicate mount targets are reported once.",
            "",
            "| Mount | Size | Used | Free | Used % | Status | Headroom to RED | Recommendation |",
            "|---|---:|---:|---:|---:|---|---:|---|",
        ]
    )
    for item in report["storage"]:
        lines.append(
            f"| {md_cell(item['mount'])} | {human_bytes(item['size_bytes'])} | "
            f"{human_bytes(item['used_bytes'])} | {human_bytes(item['free_bytes'])} | "
            f"{item['used_percent']}% | {item['threshold_status']} | "
            f"{item['headroom_to_red_points']} pp | {md_cell(item['recommendation'] or '—')} |"
        )

    lines.extend(
        [
            "",
            "## SMART / Drive Health",
            "",
            "| Device / Model | Current health | Current temperature | Evidence | Critical warning | Notable result |",
            "|---|---|---:|---|---:|---|",
        ]
    )
    for item in report["smart"]["devices"]:
        warning = "; ".join(item["warnings"]) or "None"
        temp = f"{item['temperature_c']} C" if item["temperature_c"] is not None else "UNKNOWN"
        lines.append(
            f"| {md_cell(item['device'])} / {md_cell(item['model'])} | {item['current_health']} | "
            f"{temp} | {md_cell(item['current_evidence_source'])} | {md_cell(item['critical_warning'])} | {md_cell(warning)} |"
        )
    if report["smart"]["historical_alerts"]:
        lines.append("")
        lines.append("Historical smartd alerts (not treated as proof of a current failure):")
        for alert in report["smart"]["historical_alerts"]:
            temp = f", {alert['temperature_c']} C" if alert["temperature_c"] else ""
            lines.append(
                f"- {alert['timestamp']}: {alert['device']} — {alert['type']}{temp}"
            )

    lines.extend(
        [
            "",
            "## Backup Freshness",
            "",
            "| Name | Timer triggered | Service state/result | Exit | Completed | Evidence | Status artifact | Status |",
            "|---|---|---|---:|---|---|---|---|",
        ]
    )
    for backup in report["backups"]:
        service = backup["service"]
        artifact = backup.get("status_artifact")
        artifact_text = "none" if artifact is None else f"{artifact.get('last_result', 'UNKNOWN')} @ {artifact.get('last_evidence', 'UNKNOWN')}"
        service_result = f"{service['state']} / {service['result']}"
        lines.append(
            f"| {backup['name']} | {md_cell(backup.get('timer_triggered'))} | {md_cell(service_result)} | "
            f"{md_cell(service['exit_status'])} | {md_cell(service['completed'])} | "
            f"{md_cell(service['evidence_source'])} | {md_cell(artifact_text)} | {backup['status']} |"
        )
        if backup.get("reason"):
            lines.append(f"  - {backup['name']}: {backup['reason']}.")

    lines.extend(
        [
            "",
            "## Timer / Scheduled Jobs",
            "",
            "| Timer | Enabled / known | Cadence | Next run | Previous run | Runtime verification |",
            "|---|---|---|---|---|---|",
        ]
    )
    for timer in report["timers"]:
        enabled = f"{'enabled' if timer['enabled'] else 'not enabled'} / known"
        runtime = "available" if timer["runtime_verified"] else f"UNKNOWN: {timer['runtime_unknown_reason']}"
        lines.append(
            f"| {timer['name']} | {enabled} | {md_cell(timer['cadence'])} | "
            f"{md_cell(timer['next_run'])} | {md_cell(timer['previous_run'])} | {md_cell(runtime)} |"
        )

    lines.extend(
        [
            "",
            "## Git Repository State",
            "",
            "| Repository | Branch | State | Modified | Deleted | Untracked | Upstream |",
            "|---|---|---|---:|---:|---:|---|",
        ]
    )
    for repo in report["git_repositories"]:
        if repo["upstream_available"]:
            upstream = f"ahead {repo['ahead']}, behind {repo['behind']}"
        else:
            upstream = "UNKNOWN/no upstream"
        lines.append(
            f"| {md_cell(repo['name'])} | {md_cell(repo['branch'])} | "
            f"{'DIRTY' if repo['dirty'] else 'CLEAN'} | {repo['modified']} | {repo['deleted']} | "
            f"{repo['untracked']} | {upstream} |"
        )

    lines.extend(
        [
            "",
            "## Critical Anomaly Summary",
            "",
        ]
    )
    if report["anomalies"]:
        lines.extend(f"- **{a['severity']}** {a['message']}" for a in report["anomalies"])
    else:
        lines.append("No anomalies detected.")
    return "\n".join(lines) + "\n"


def exit_code(status: str) -> int:
    if status == "RED":
        return 2
    if status in {"YELLOW", "UNKNOWN"}:
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--markdown", action="store_true", help="render Markdown (default)")
    output.add_argument("--json", action="store_true", help="render machine-readable JSON")
    args = parser.parse_args()
    report = collect_report()
    if args.json:
        json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_markdown(report))
    return exit_code(report["overall_status"])


if __name__ == "__main__":
    raise SystemExit(main())
