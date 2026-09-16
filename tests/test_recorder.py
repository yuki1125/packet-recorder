import json
from pathlib import Path
import signal
import struct
import subprocess
from unittest.mock import Mock

import pytest

from packet_recorder.cli import Config, parse_args
from packet_recorder.recorder import command, stop_process, run
from packet_recorder.rotation import rotation_args
from packet_recorder.stats import scan_capture, parse_dumpcap_statistics


def test_unfiltered_command():
    config = Config(["enp4s0"], rotate_seconds=600, rotate_size_mb=1024)
    cmd = command(config, Path("capture.pcapng"))
    assert "-f" not in cmd and "-p" in cmd and "-s" in cmd
    assert "EN10MB" in cmd and "-n" in cmd
    assert rotation_args(config) == ["-b", "duration:600", "-b", "filesize:1024000"]
    assert not any(x.startswith("files:") for x in cmd)
    assert "-p" not in command(Config(["eth0"], promiscuous=True), Path("x.pcapng"))


def test_cli_format():
    assert parse_args(["--interface", "eth0", "--output", "x.pcap"]).format == "pcap"
    assert parse_args(["--interface", "eth0"]).format == "pcapng"
    with pytest.raises(SystemExit):
        parse_args(["--interface", "eth0", "--output", "x.pcap", "--format", "pcapng"])
    with pytest.raises(SystemExit):
        parse_args(["--interface", "eth0", "--output", "x.pcap", "--output-dir", "logs"])


@pytest.mark.parametrize("values", [dict(interfaces=[]), dict(interfaces=["a", "b"]),
    dict(interfaces=["eth0"], min_free_gb=float("nan")),
    dict(interfaces=["eth0"], buffer_mb=0), dict(interfaces=["eth0"], rotate_seconds=-1),
    dict(interfaces=["eth0"], duration=float("inf"))])
def test_invalid_configuration(values):
    with pytest.raises(ValueError):
        Config(**values).validate()


def test_shutdown_and_forced_shutdown(monkeypatch):
    monkeypatch.setattr("packet_recorder.backend.sys.platform", "linux")
    process = Mock()
    process.poll.return_value = None
    assert stop_process(process) is False
    process.send_signal.assert_called_once_with(signal.SIGINT)
    process.wait.side_effect = [subprocess.TimeoutExpired("dumpcap", 10), 0]
    assert stop_process(process) is True
    process.kill.assert_called_once()


def test_unknown_drops_and_modern_statistics():
    assert parse_dumpcap_statistics("Packets captured: 7")["kernel_drops"] is None
    stats = parse_dumpcap_statistics("Packets captured: 7\nPackets dropped: 5 (pcap:3 dumpcap:2)")
    assert stats == {"dumpcap_packets": 7, "kernel_drops": 3, "capture_drops": 2,
                     "flushed_drops": None, "reported_interface_drops": None}


def test_loss_is_warned(tmp_path, monkeypatch, fake_preflight, capsys):
    monkeypatch.setattr("packet_recorder.recorder.free_space_ok", lambda *a: True)
    path = tmp_path / "a.pcap"
    def spawn(*args, **kwargs):
        write_pcap(path)
        kwargs["stderr"].write("Packets captured: 1\nPackets dropped (pcap:3/dumpcap:2/flushed:1/ps_ifdrop:4)\n")
        proc = Mock(returncode=0)
        proc.poll.return_value = 0
        return proc
    monkeypatch.setattr("packet_recorder.recorder.subprocess.Popen", spawn)
    assert run(Config(["eth0"], output=path, format="pcap")) == 0
    result = json.loads(path.with_suffix(".json").read_text())
    assert result["kernel_drops"] == 3 and result["reported_interface_drops"] == 4
    assert len(result["warnings"]) == 4 and "WARNING" in capsys.readouterr().err


def write_pcap(path):
    path.write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
                     + struct.pack("<IIII", 1700000000, 123456, 4, 4) + b"abcd")


def test_container_accounting_and_truncation(tmp_path):
    path = tmp_path / "a.pcap"
    write_pcap(path)
    stats = scan_capture(path)
    assert stats["packets"] == 1 and stats["captured_bytes"] == 4
    assert stats["file_bytes"] == 44 and stats["truncated_packets"] == 0
    assert stats["interfaces"][0]["timestamp_resolution"] == "1/1000000"
    path.write_bytes(path.read_bytes()[:-1])
    with pytest.raises(ValueError, match="truncated"):
        scan_capture(path)


@pytest.fixture
def fake_preflight(monkeypatch):
    monkeypatch.setattr("packet_recorder.backend.sys.platform", "linux")
    monkeypatch.setattr("packet_recorder.recorder.preflight", lambda c: ([{"name": "eth0"}], "fake", {}, c))


def test_low_disk_does_not_start(tmp_path, monkeypatch, fake_preflight):
    monkeypatch.setattr("packet_recorder.recorder.free_space_ok", lambda *a: False)
    spawn = Mock()
    monkeypatch.setattr("packet_recorder.recorder.subprocess.Popen", spawn)
    assert run(Config(["eth0"], output=tmp_path / "a.pcapng")) == 1
    spawn.assert_not_called()
    data = json.loads((tmp_path / "a.json").read_text())
    assert data["status"] == "insufficient_disk_space"
    assert data["kernel_drops"] is None


def test_existing_files_never_overwritten(tmp_path, fake_preflight):
    path = tmp_path / "a.pcapng"
    path.write_bytes(b"precious")
    with pytest.raises(FileExistsError):
        run(Config(["eth0"], output=path))
    assert path.read_bytes() == b"precious"
    assert not (tmp_path / "a.lock").exists()


def test_capture_error_metadata(tmp_path, monkeypatch, fake_preflight):
    monkeypatch.setattr("packet_recorder.recorder.free_space_ok", lambda *a: True)
    process = Mock(returncode=2)
    process.poll.return_value = 2
    monkeypatch.setattr("packet_recorder.recorder.subprocess.Popen", lambda *a, **k: process)
    assert run(Config(["eth0"], output=tmp_path / "a.pcapng")) == 1
    data = json.loads((tmp_path / "a.json").read_text())
    assert data["status"] == "capture_error" and data["dumpcap_exit_code"] == 2


def test_runtime_disk_exhaustion_closes_capture(tmp_path, monkeypatch, fake_preflight):
    checks = iter([True, False])
    monkeypatch.setattr("packet_recorder.recorder.free_space_ok", lambda *a: next(checks))
    process = Mock(returncode=0)
    process.poll.side_effect = [None, None]
    monkeypatch.setattr("packet_recorder.recorder.subprocess.Popen", lambda *a, **k: process)
    assert run(Config(["eth0"], output=tmp_path / "a.pcapng")) == 1
    process.send_signal.assert_called_once_with(signal.SIGINT)
    assert json.loads((tmp_path / "a.json").read_text())["status"] == "insufficient_disk_space"


def test_missing_interface_stops_capture(tmp_path, monkeypatch, fake_preflight):
    monkeypatch.setattr("packet_recorder.recorder.free_space_ok", lambda *a: True)
    monkeypatch.setattr("packet_recorder.recorder.socket.if_nameindex", lambda: [])
    process = Mock(returncode=0)
    process.poll.side_effect = [None, None]
    monkeypatch.setattr("packet_recorder.recorder.subprocess.Popen", lambda *a, **k: process)
    assert run(Config(["eth0"], output=tmp_path / "a.pcapng")) == 1
    assert json.loads((tmp_path / "a.json").read_text())["status"] == "interface_disappeared"


@pytest.mark.parametrize("endian,resolution", [("<", 9), (">", 0x8a)])
def test_pcapng_timestamps_and_isb(tmp_path, endian, resolution):
    def block(kind, body):
        length = len(body) + 12
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)
    shb = block(0x0a0d0d0a, struct.pack(endian + "IHHq", 0x1a2b3c4d, 1, 0, -1))
    idb = block(1, struct.pack(endian + "HHIHH", 1, 0, 65535, 9, 1)
                + bytes([resolution, 0, 0, 0]) + bytes(4))
    epb = block(6, struct.pack(endian + "IIIII", 0, 0, 123456, 4, 4) + b"abcd")
    isb = block(5, struct.pack(endian + "IIIHHQ", 0, 0, 123456, 5, 8, 3) + bytes(4))
    path = tmp_path / "a.pcapng"
    path.write_bytes(shb + idb + epb + isb)
    result = scan_capture(path)
    assert result["captured_bytes"] == 4
    assert result["interfaces"][0]["timestamp_resolution"] == ("1/1000000000" if resolution == 9 else "1/1024")
    assert result["interface_statistics"] == [{"interface_id": 0, "ifdrop": 3}]
