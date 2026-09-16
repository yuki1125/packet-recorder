from pathlib import Path
import json
import subprocess
import sys
import time
from unittest.mock import Mock

import pytest

from packet_recorder import backend, interfaces
from packet_recorder.cli import Config
from packet_recorder.recorder import preflight

GUID = "01234567-89AB-CDEF-0123-456789ABCDEF"
DEVICE = "\\Device\\NPF_{" + GUID + "}"


def test_windows_guid_mapping_and_unicode(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    output = f"1. {DEVICE} (Ethernet)\n2. \\Device\\NPF_Loopback (loopback)\n3. usbpcap1 (USB)\n"
    details = [{"guid": GUID.lower(), "name": "イーサネット", "index": 12,
                "mac": "01-02-03-04-05-06", "ipv4": ["192.0.2.1"], "state": "Up"}]
    items = interfaces.parse_windows_interfaces(output, details)
    assert len(items) == 1 and items[0]["name"] == DEVICE
    assert items[0]["ipv4"] == ["192.0.2.1"]
    for alias in (DEVICE.lower(), "1", "イーサネット"):
        assert interfaces.select_interface(items, alias)["name"] == DEVICE
    with pytest.raises(ValueError):
        interfaces.select_interface(items, "2")
    monkeypatch.setattr(interfaces.socket, "if_nameindex", lambda: [(12, "ethernet_0")])
    assert interfaces.interface_present(items[0])
    monkeypatch.setattr(interfaces.socket, "if_nameindex", lambda: [])
    assert not interfaces.interface_present(items[0])


def test_windows_duplicate_alias_rejected(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    items = [{"name": "a", "display_name": "Ethernet", "capture_index": 1},
             {"name": "b", "display_name": "Ethernet", "capture_index": 2}]
    with pytest.raises(ValueError):
        interfaces.select_interface(items, "Ethernet")


def test_windows_executable_discovery(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(backend.shutil, "which", lambda value: None)
    for key in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        monkeypatch.delenv(key, raising=False)
    executable = tmp_path / "Program Files" / "Wireshark" / "dumpcap.exe"
    executable.parent.mkdir(parents=True)
    executable.touch()
    monkeypatch.setenv("ProgramFiles", str(executable.parents[1]))
    assert backend.resolve_dumpcap() == str(executable)
    # An explicit missing path must not silently fall back to a different executable.
    with pytest.raises(FileNotFoundError):
        backend.resolve_dumpcap("missing/custom-dumpcap.exe")


def test_windows_missing_dependencies(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(backend.shutil, "which", lambda value: None)
    for key in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(FileNotFoundError, match="Wireshark with Npcap"):
        backend.resolve_dumpcap()


def test_windows_metadata_fallback(monkeypatch):
    monkeypatch.setattr(interfaces, "quiet_options", lambda: {})
    monkeypatch.setattr(interfaces.subprocess, "run", lambda *a, **kw:
                        Mock(returncode=0, stdout=f"1. {DEVICE} (Ethernet)\n", stderr=""))
    def failure():
        raise OSError("OS metadata unavailable")
    monkeypatch.setattr(interfaces, "windows_adapter_details", failure)
    items = interfaces.windows_interfaces("dumpcap.exe")
    assert items[0]["name"] == DEVICE and items[0]["link_state"] == "UNKNOWN"


def test_preflight_resolves_alias_and_preserves_config(monkeypatch):
    import packet_recorder.recorder as recorder
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(recorder, "resolve_dumpcap", lambda _: "C:/Program Files/Wireshark/dumpcap.exe")
    monkeypatch.setattr(recorder, "quiet_options", lambda: {})
    monkeypatch.setattr(recorder, "list_interfaces", lambda _: interfaces.parse_windows_interfaces(f"1. {DEVICE} (Ethernet)", []))
    responses = iter([Mock(stdout="Dumpcap 4.6\n"), Mock(stdout="1. EN10MB (Ethernet)", stderr="")])
    monkeypatch.setattr(recorder.subprocess, "run", lambda *a, **kw: next(responses))
    config = Config(["Ethernet"])
    selected, version, env, resolved = preflight(config)
    assert resolved.interfaces == [DEVICE] and config.interfaces == ["Ethernet"]
    assert resolved.dumpcap == "C:/Program Files/Wireshark/dumpcap.exe"


def test_windows_failed_signal_uses_forced_stop(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(backend, "quiet_options", lambda: {})
    def failure(*args, **kwargs):
        raise subprocess.CalledProcessError(1, "signal helper")
    monkeypatch.setattr(backend.subprocess, "run", failure)
    process = Mock(pid=123)
    process.poll.return_value = None
    assert backend.stop_process(process) is True
    process.kill.assert_called_once()


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows supervisor lifecycle")
def test_native_windows_low_disk_closes_child_and_metadata(tmp_path, monkeypatch):
    import packet_recorder.recorder as recorder
    fixture = Path(__file__).parent / "fixtures" / "control_child.py"
    output = tmp_path / "日本語の記録.pcap"
    config = Config([DEVICE], output=output, format="pcap")
    monkeypatch.setattr(recorder, "preflight", lambda c: ([{"name": DEVICE}], "fixture", {}, c))
    monkeypatch.setattr(recorder, "command", lambda *args:
                        [sys.executable, str(fixture), str(output), "--pcap-fixture"])
    first_check = True
    def disk_check(*args):
        nonlocal first_check
        if first_check:
            first_check = False
            return True
        deadline = time.monotonic() + 10
        while not output.with_suffix(".ready").exists():
            assert time.monotonic() < deadline
            time.sleep(0.05)
        return False
    monkeypatch.setattr(recorder, "free_space_ok", disk_check)
    assert recorder.run(config) == 1
    metadata = json.loads(output.with_suffix(".json").read_text(encoding="utf-8"))
    assert metadata["status"] == "insufficient_disk_space"
    assert metadata["dumpcap_exit_code"] == 0 and metadata["packet_count"] == 1
    assert metadata["kernel_drops"] == 0 and metadata["files"][0]["truncated_packets"] == 0


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows console control")
def test_native_windows_graceful_stop_is_isolated(tmp_path):
    fixture = Path(__file__).parent / "fixtures" / "control_child.py"
    first = tmp_path / "first.closed"
    second = tmp_path / "second.closed"
    children = []
    try:
        for marker in (first, second):
            child = subprocess.Popen([sys.executable, str(fixture), str(marker)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     **backend.capture_process_options())
            children.append(child)
            deadline = time.monotonic() + 10
            while not marker.with_suffix(".ready").exists():
                assert child.poll() is None and time.monotonic() < deadline
                time.sleep(0.05)
        assert backend.stop_process(children[0]) is False
        assert children[0].returncode == 0 and first.read_text() == "closed normally"
        assert children[1].poll() is None and not second.exists()
        assert backend.stop_process(children[1]) is False
        assert second.read_text() == "closed normally"
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait()
