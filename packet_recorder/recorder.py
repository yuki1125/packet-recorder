"""Supervise a native capture process, never consume application sockets."""
from dataclasses import asdict, replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

from . import __version__
from .interfaces import list_interfaces, select_interface, interface_present
from .backend import resolve_dumpcap, quiet_options, capture_process_options, stop_process
from .rotation import output_path, rotation_args, capture_files
from .stats import parse_dumpcap_statistics, scan_capture


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def command(config, path):
    cmd = [config.dumpcap, "-q", "-i", config.interfaces[0], "-y", "EN10MB",
           "-s", "0", "-B", str(config.buffer_mb)]
    if not config.promiscuous:
        cmd += ["-p"]
    # -n/-P also support Ubuntu 22.04's dumpcap 3.6; -F was introduced later.
    cmd += ["-n" if config.format == "pcapng" else "-P", "-w", str(path)]
    cmd += rotation_args(config)
    if config.duration:
        cmd += ["-a", f"duration:{config.duration:g}"]
    return cmd


def free_space_ok(directory, min_gb):
    return shutil.disk_usage(directory).free >= min_gb * 1024**3


def write_metadata(path, metadata):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=path.name + ".", suffix=".tmp", delete=False) as f:
            temporary = Path(f.name)
            json.dump(metadata, f, indent=2, ensure_ascii=False, default=str)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def preflight(config):
    config.validate()
    if sys.platform not in ("linux", "win32"):
        raise ValueError("capture requires Linux or Windows")
    executable = resolve_dumpcap(config.dumpcap)
    selected = [select_interface(list_interfaces(executable), config.interfaces[0])]
    config = replace(config, dumpcap=executable, interfaces=[selected[0]["name"]])
    env = dict(os.environ, LC_ALL="C", LANG="C")
    version = subprocess.run([config.dumpcap, "--version"], capture_output=True,
                             text=True, encoding="utf-8", errors="replace", check=True,
                             timeout=10, env=env, **quiet_options()).stdout.splitlines()[0]
    links = subprocess.run([config.dumpcap, "-i", config.interfaces[0], "-L"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace",
                           check=True, timeout=10, env=env, **quiet_options())
    if "EN10MB" not in links.stdout + links.stderr:
        raise ValueError("interface does not offer Ethernet EN10MB capture")
    return selected, version, env, config


def run(config):
    selected, version, env, config = preflight(config)
    base = output_path(config)
    base.parent.mkdir(parents=True, exist_ok=True)
    rotating = bool(config.rotate_seconds or config.rotate_size_mb)
    metadata_path = base.with_suffix(".json")
    log_path = base.with_suffix(".stderr.log")
    lock_path = base.with_suffix(".lock")
    # Exclusive reservation prevents two Recorder sessions claiming the same prefix.
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    process = None
    handlers = {}
    requested = []
    metadata = {"schema_version": 1, "software_version": __version__,
                "dumpcap_version": version, "hostname": socket.gethostname(),
                "start_time": utc_now(), "end_time": None, "interfaces": config.interfaces,
                "interface_details": selected, "config": asdict(config),
                "capture_filter": None, "clock_source": "unknown (libpcap default)",
                "status": "starting", "files": [], "warnings": [],
                "metadata_path": str(metadata_path), "stderr_log": str(log_path)}
    started = time.monotonic()
    try:
        if any(os.path.lexists(p) for p in (base, metadata_path, log_path)) or capture_files(base, rotating):
            raise FileExistsError(f"capture output/session already exists: {base}")
        write_metadata(metadata_path, metadata)
        if not free_space_ok(base.parent, config.min_free_gb):
            metadata["status"] = "insufficient_disk_space"
            metadata["warnings"].append("free disk space below configured minimum; capture not started")
        else:
            signals = [signal.SIGINT, signal.SIGTERM]
            if sys.platform == "win32":
                signals.append(signal.SIGBREAK)
            for sig in signals:
                handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, lambda number, frame: requested.append(number))
            with log_path.open("x", encoding="utf-8") as log:
                process = subprocess.Popen(command(config, base), stdout=log, stderr=log,
                                           env=env, **capture_process_options())
                metadata["status"] = "recording"
                metadata["command"] = command(config, base)
                write_metadata(metadata_path, metadata)
                print(f"STARTING interface={config.interfaces[0]} output={base} metadata={metadata_path}", flush=True)
                next_check = time.monotonic()
                while process.poll() is None:
                    if requested:
                        metadata["status"] = "stopped_by_signal"
                        metadata["signal"] = requested[0]
                        break
                    if time.monotonic() >= next_check:
                        next_check = time.monotonic() + 1
                        if not free_space_ok(base.parent, config.min_free_gb):
                            metadata["status"] = "insufficient_disk_space"
                            metadata["warnings"].append("free disk space below configured minimum")
                            print("WARNING: low disk space; stopping capture now", file=sys.stderr, flush=True)
                            break
                        if not interface_present(selected[0]):
                            metadata["status"] = "interface_disappeared"
                            metadata["warnings"].append("capture interface disappeared")
                            break
                    time.sleep(0.2)
                if stop_process(process):
                    metadata["status"] = "forced_termination"
                    metadata["warnings"].append("graceful dumpcap shutdown failed; file integrity is not guaranteed")
                metadata["dumpcap_exit_code"] = process.returncode
                if metadata["status"] == "recording":
                    metadata["status"] = "completed" if process.returncode == 0 else "capture_error"
                elif process.returncode != 0 and metadata["status"] == "stopped_by_signal":
                    metadata["status"] = "capture_error"
        metadata["capture_duration_seconds"] = time.monotonic() - started
        metadata["end_time"] = utc_now()
        metadata.update(parse_dumpcap_statistics(log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""))
        # Persist the stop before the potentially long, bounded-memory final accounting pass.
        write_metadata(metadata_path, metadata)
        for path in capture_files(base, rotating):
            try:
                metadata["files"].append(scan_capture(path))
            except (OSError, ValueError, IndexError, ArithmeticError, struct.error) as exc:
                metadata["files"].append({"path": str(path), "error": str(exc)})
                metadata["warnings"].append(f"capture validation failed: {path}: {exc}")
                metadata["status"] = "invalid_capture"
        metadata["packet_count"] = sum(f.get("packets", 0) for f in metadata["files"])
        metadata["captured_bytes"] = sum(f.get("captured_bytes", 0) for f in metadata["files"])
        metadata["file_bytes"] = sum(f.get("file_bytes", 0) for f in metadata["files"])
        elapsed = metadata["capture_duration_seconds"]
        metadata["average_packets_per_second"] = metadata["packet_count"] / elapsed if elapsed else 0
        metadata["average_mb_per_second"] = metadata["captured_bytes"] / 1e6 / elapsed if elapsed else 0
        for key in ("kernel_drops", "capture_drops", "flushed_drops", "reported_interface_drops"):
            if metadata.get(key):
                metadata["warnings"].append(f"packet loss reported: {key}={metadata[key]}")
        if metadata.get("dumpcap_packets") is not None and metadata["dumpcap_packets"] != metadata["packet_count"]:
            metadata["warnings"].append("dumpcap count and saved packet count disagree")
            metadata["status"] = "statistics_mismatch"
        if any(f.get("truncated_packets", 0) for f in metadata["files"]):
            metadata["warnings"].append("truncated packets found; inspect snaplen and capture backend")
        if metadata["status"] in ("completed", "stopped_by_signal") and not metadata["files"]:
            metadata["status"] = "capture_error"
            metadata["warnings"].append("dumpcap produced no capture file")
        write_metadata(metadata_path, metadata)
        for warning in metadata["warnings"]:
            print(f"WARNING: {warning}", file=sys.stderr)
        print(json.dumps(metadata, indent=2, default=str))
        return 0 if metadata["status"] in ("completed", "stopped_by_signal") else 1
    except BaseException as exc:
        if process is not None:
            forced = stop_process(process)
            metadata["forced_termination"] = forced
        # Do not overwrite metadata belonging to a prior session on collisions.
        if not isinstance(exc, FileExistsError):
            metadata.update(status="supervisor_error", end_time=utc_now(), error=str(exc))
            try:
                write_metadata(metadata_path, metadata)
            except OSError:
                pass
        raise
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        os.close(lock_fd)
        lock_path.unlink(missing_ok=True)
