"""Console shutdown fixture. This is not a packet capture backend."""
from pathlib import Path
import signal
import struct
import sys
import time

marker = Path(sys.argv[1])
stopped = False


def stop(number, frame):
    global stopped
    stopped = True


signal.signal(signal.SIGBREAK, stop)
if "--pcap-fixture" in sys.argv:
    # Synthetic container for supervisor lifecycle tests; no network capture is claimed.
    with marker.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        output.flush()
        marker.with_suffix(".ready").write_text("ready")
        while not stopped:
            time.sleep(0.05)
        output.write(struct.pack("<IIII", 1700000000, 123456, 4, 4) + b"test")
    print("Packets captured: 1", flush=True)
    print("Packets dropped (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0)", flush=True)
else:
    marker.with_suffix(".ready").write_text("ready")
    while not stopped:
        time.sleep(0.05)
    marker.write_text("closed normally")
