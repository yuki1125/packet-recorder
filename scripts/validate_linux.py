"""Opt-in root integration harness; uses ONLY disposable, isolated network namespaces.

Run with --e1r-project /path/to/robosense-e1r-decoder. No host NIC is captured.
No capabilities, sudoers, sysctls, or existing NICs are modified.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time
from uuid import uuid4


def send(payload_file, count):
    payloads = json.loads(Path(payload_file).read_text())
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for port in (6699, 7788, 5000, 6000):
        for payload in payloads.get(str(port), [b"generic-sensor".hex()]):
            udp.sendto(bytes.fromhex(payload), ("192.0.2.1", port))
            time.sleep(0.002)
    udp6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    udp6.sendto(b"ipv6-sensor", ("fd00:1234::1", 5000))
    with socket.create_connection(("192.0.2.1", 5001), timeout=2) as tcp:
        tcp.sendall(b"tcp-sensor")
    started = time.monotonic()
    for index in range(count):
        udp.sendto(b"PRLOAD" + struct.pack("!I", index) + bytes(1014), ("192.0.2.1", 6000))
    return {"load_packets_sent": count, "load_payload_bytes": count * 1024,
            "load_send_seconds": time.monotonic() - started}


def listen():
    import selectors
    selector = selectors.DefaultSelector()
    for family, address in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "fd00:1234::1")):
        for port in (5000, 6000):
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.bind((address, port))
            selector.register(sock, selectors.EVENT_READ)
    tcp = socket.socket()
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("192.0.2.1", 5001))
    tcp.listen()
    selector.register(tcp, selectors.EVENT_READ)
    print("READY", flush=True)
    while True:
        for key, _ in selector.select():
            if key.fileobj is tcp:
                conn, _ = tcp.accept()
                conn.recv(4096)
                conn.close()
            else:
                key.fileobj.recvfrom(65535)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--e1r-project", type=Path)
    p.add_argument("--output", type=Path, default=Path("validation-artifacts"))
    p.add_argument("--send", type=Path)
    p.add_argument("--count", type=int, default=20000)
    p.add_argument("--listen", action="store_true")
    args = p.parse_args()
    if args.send:
        print(json.dumps(send(args.send, args.count)))
        return
    if args.listen:
        listen()
        return
    if os.geteuid() != 0 or not args.e1r_project:
        p.error("root and --e1r-project are required for disposable namespace tests")
    repo = Path(__file__).resolve().parents[1]
    output = (args.output / time.strftime("%Y%m%d_%H%M%S") / uuid4().hex[:8]).resolve()
    output.mkdir(parents=True)
    sys.path.insert(0, str(args.e1r_project.resolve()))
    from e1r_decoder.pcap import read_pcap
    from e1r_decoder.constants import DIFOP_MAGIC
    msop = []
    for record in read_pcap(args.e1r_project / "testdata/e1r_frames.pcap"):
        if record.destination_port == 6699:
            msop.append(record.payload.hex())
        if len(msop) == 100:
            break
    assert len(msop) == 100
    difop = bytearray(256)
    difop[:8] = DIFOP_MAGIC
    difop[103:109] = (1700000000).to_bytes(6, "big")
    struct.pack_into(">6f", difop, 208, 1, 2, 3, 4, 5, 6)
    payload_file = output / "payloads.json"
    payload_file.write_text(json.dumps({"6699": msop, "7788": [difop.hex()]}))
    tag = uuid4().hex[:6]
    a, b = "pr-a-" + tag, "pr-b-" + tag
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(repo), str(args.e1r_project.resolve())]))
    children = []
    created = []
    results = {"platform": sys.platform, "kernel": os.uname().release,
               "dumpcap": subprocess.check_output(["dumpcap", "--version"], text=True).splitlines()[0],
               "cases": []}

    def checked(cmd, **kwargs):
        return subprocess.run(cmd, check=True, capture_output=True, text=True, env=env, **kwargs)

    def ns(name, cmd):
        return ["ip", "netns", "exec", name, *cmd]

    def launch(name, cmd, logfile):
        handle = logfile.open("w")
        child = subprocess.Popen(ns(name, cmd), stdout=handle, stderr=subprocess.STDOUT, env=env)
        handle.close()
        children.append(child)
        return child

    def wait_text(path, needle, child):
        until = time.monotonic() + 15
        while time.monotonic() < until:
            try:
                if path.exists() and needle in path.read_text(errors="replace"):
                    return
            except OSError as exc:
                # WSL DrvFS can transiently report ENODATA for a just-created, growing log.
                if exc.errno != errno.ENODATA:
                    raise
            if child.poll() is not None:
                raise AssertionError(f"process exited: {path.read_text(errors='replace')}")
            time.sleep(0.1)
        raise AssertionError(f"timeout waiting for {needle}: {path}")

    try:
        for name in (a, b):
            checked(["ip", "netns", "add", name])
            created.append(name)
        # Both endpoints are created directly inside namespaces; no host route changes.
        checked(["ip", "-n", a, "link", "add", "capture0", "type", "veth", "peer", "name", "sensor0", "netns", b])
        for name, nic, number in ((a, "capture0", 1), (b, "sensor0", 2)):
            checked(["ip", "-n", name, "addr", "add", f"192.0.2.{number}/24", "dev", nic])
            checked(["ip", "-n", name, "addr", "add", f"fd00:1234::{number}/64", "dev", nic, "nodad"])
            checked(["ip", "-n", name, "link", "set", nic, "up"])
            checked(["ip", "-n", name, "link", "set", "lo", "up"])
        listener_log = output / "listener.log"
        listener = launch(a, [sys.executable, __file__, "--listen"], listener_log)
        wait_text(listener_log, "READY", listener)
        cases = [("pcapng", [], signal.SIGINT, 0), ("pcap", [], signal.SIGTERM, 0),
                 ("time", ["--rotate-seconds", "1"], signal.SIGTERM, 0),
                 ("size", ["--rotate-size-mb", "0.05"], signal.SIGINT, 0),
                 ("load", [], signal.SIGTERM, args.count)]
        for name, rotation, stop_signal, count in cases:
            for space, nic in ((a, "capture0"), (b, "sensor0")):
                checked(["ip", "-n", space, "neigh", "flush", "dev", nic])
            fmt = "pcap" if name == "pcap" else "pcapng"
            capture = output / f"{name}.{fmt}"
            console = output / f"{name}.console.log"
            recorder = launch(a, [sys.executable, "-m", "packet_recorder.record",
                "--interface", "capture0", "--output", str(capture), "--min-free-gb", "0", *rotation], console)
            wait_text(capture.with_suffix(".stderr.log"), "File:", recorder)
            live_log = output / f"{name}.live.log"
            live_stats = output / f"{name}.live.json"
            live = launch(a, [sys.executable, "-m", "e1r_decoder.live", "--bind-ip", "192.0.2.1",
                 "--max-packets", "101", "--duration", "10", "--stats-json", str(live_stats)], live_log)
            wait_text(live_log, "READY", live)
            sent = json.loads(checked(ns(b, [sys.executable, __file__, "--send", str(payload_file), "--count", str(count)])).stdout)
            checked(ns(b, ["ping", "-c", "1", "-W", "2", "192.0.2.1"]))
            checked(ns(b, ["ping", "-6", "-c", "1", "-W", "2", "fd00:1234::1"]))
            assert live.wait(timeout=15) == 0
            if name == "time":
                time.sleep(2.2)
                checked(ns(b, ["ping", "-c", "1", "192.0.2.1"]))
            # Allow libpcap's buffered delivery before ending the measurement window.
            # A signal stops capture; it cannot promise to drain frames still in the NIC/kernel.
            time.sleep(1.5)
            recorder.send_signal(stop_signal)
            assert recorder.wait(timeout=40) == 0, console.read_text()
            metadata = json.loads(capture.with_suffix(".json").read_text())
            assert metadata["packet_count"] > 0 and not metadata["warnings"], metadata
            assert metadata["kernel_drops"] == 0, metadata
            records = []
            fields = []
            offline = {"valid_msop": 0, "valid_difop": 0}
            for item in metadata["files"]:
                path = item["path"]
                assert item["truncated_packets"] == 0
                assert all(i["link_type"] == 1 for i in item["interfaces"])
                rows = checked(["tshark", "-r", path, "-T", "fields", "-e", "eth.src", "-e", "eth.dst",
                   "-e", "ip.src", "-e", "udp.dstport", "-e", "tcp.dstport", "-e", "arp.opcode",
                   "-e", "icmp.type", "-e", "ipv6.src", "-e", "frame.time_epoch", "-e", "udp.payload"]).stdout
                fields.extend(line.split("\t") for line in rows.splitlines())
                records.extend(read_pcap(path))
                stats_path = output / (Path(path).name + ".decoded.json")
                checked([sys.executable, "-m", "e1r_decoder.decode_pcap", "--pcap", path, "--stats-json", str(stats_path)])
                stats = json.loads(stats_path.read_text())
                for key in offline:
                    offline[key] += stats[key]
            assert {6699, 7788, 5000, 6000} <= {r.destination_port for r in records}
            assert [r.payload.hex() for r in records if r.destination_port == 6699] == msop
            assert [r.payload for r in records if r.destination_port == 7788] == [bytes(difop)]
            assert all(len(row) == 10 and row[0] and row[1] and float(row[8]) > 1_700_000_000 for row in fields)
            assert {"192.0.2.1", "192.0.2.2"} <= {row[2] for row in fields}
            assert any(row[4] for row in fields) and any(row[5] for row in fields)
            assert any(row[6] for row in fields) and any(row[7] for row in fields)
            load_indices = [struct.unpack("!I", r.payload[6:10])[0] for r in records if r.payload.startswith(b"PRLOAD")]
            assert len(load_indices) == count and set(load_indices) == set(range(count))
            assert offline == {"valid_msop": 100, "valid_difop": 1}
            live_data = json.loads(live_stats.read_text())
            assert all(live_data[k] == v for k, v in offline.items())
            if rotation:
                assert len(metadata["files"]) >= 2
            results["cases"].append({"name": name, "status": "PASS", "packets": metadata["packet_count"],
                "files": len(metadata["files"]), "kernel_drops": metadata["kernel_drops"],
                "capture_drops": metadata["capture_drops"], "captured_bytes": metadata["captured_bytes"],
                "duration": metadata["capture_duration_seconds"], "offline": offline, **sent})
            print(json.dumps(results["cases"][-1]), flush=True)
        # Actual preflight disk refusal, before starting dumpcap.
        low = checked(ns(a, [sys.executable, "-m", "packet_recorder.interfaces"]))
        assert "capture0" in low.stdout
        disk = subprocess.run(ns(a, [sys.executable, "-m", "packet_recorder.record", "--interface", "capture0",
             "--output", str(output / "disk.pcapng"), "--min-free-gb", "1000000000"]), env=env, capture_output=True, text=True)
        assert disk.returncode == 1 and not (output / "disk.pcapng").exists()
        assert json.loads((output / "disk.json").read_text())["status"] == "insufficient_disk_space"
        results["disk_refusal"] = "PASS"
        # Stop only Recorder midway; the independent live decoder must keep receiving.
        capture = output / "independent.pcapng"
        console = output / "independent.console.log"
        recorder = launch(a, [sys.executable, "-m", "packet_recorder.record", "--interface", "capture0",
             "--output", str(capture), "--min-free-gb", "0"], console)
        wait_text(capture.with_suffix(".stderr.log"), "File:", recorder)
        live_log = output / "independent.live.log"
        live_stats = output / "independent.live.json"
        live = launch(a, [sys.executable, "-m", "e1r_decoder.live", "--bind-ip", "192.0.2.1",
             "--max-packets", "202", "--duration", "15", "--stats-json", str(live_stats)], live_log)
        wait_text(live_log, "READY", live)
        checked(ns(b, [sys.executable, __file__, "--send", str(payload_file), "--count", "0"]))
        time.sleep(1.5)
        recorder.send_signal(signal.SIGTERM)
        assert recorder.wait(timeout=40) == 0 and live.poll() is None
        checked(ns(b, [sys.executable, __file__, "--send", str(payload_file), "--count", "0"]))
        assert live.wait(timeout=20) == 0
        data = json.loads(live_stats.read_text())
        assert data["valid_msop"] == 200 and data["valid_difop"] == 2
        results["decoder_survives_recorder_stop"] = "PASS"
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        for name in reversed(created):
            subprocess.run(["ip", "netns", "delete", name], check=True)
        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        print(f"Results: {output / 'results.json'}", flush=True)


if __name__ == "__main__":
    main()
