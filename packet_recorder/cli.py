import argparse
import math
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    interfaces: list[str]
    output: Path | None = None
    output_dir: Path = Path("logs")
    format: str = "pcapng"
    rotate_seconds: float | None = None
    rotate_size_mb: float | None = None
    buffer_mb: int = 64
    promiscuous: bool = False
    min_free_gb: float = 10
    duration: float | None = None
    dumpcap: str = "dumpcap"

    def validate(self):
        if len(self.interfaces) != 1 or not self.interfaces[0]:
            raise ValueError("v1 requires exactly one Ethernet interface; multi-interface/SocketCAN not implemented")
        if self.format not in ("pcap", "pcapng"):
            raise ValueError("format must be pcap or pcapng")
        for name in ("rotate_seconds", "rotate_size_mb", "buffer_mb", "duration"):
            value = getattr(self, name)
            if value is not None and (not math.isfinite(value) or value <= 0):
                raise ValueError(f"{name} must be finite and positive")
        if not math.isfinite(self.min_free_gb) or self.min_free_gb < 0:
            raise ValueError("min_free_gb must be finite and nonnegative")
        if self.rotate_size_mb is not None and self.rotate_size_mb > 2_000_000:
            raise ValueError("rotation exceeds dumpcap's 2 TB limit")
        if self.output and self.output.suffix.lower() not in (".pcap", ".pcapng"):
            raise ValueError("output must have .pcap or .pcapng extension")
        if self.output and self.output.suffix.lower() != "." + self.format:
            raise ValueError("output extension and format disagree")


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Record all Ethernet traffic on a Linux or Windows NIC")
    p.add_argument("--interface", action="append", required=True, dest="interfaces")
    output = p.add_mutually_exclusive_group()
    output.add_argument("--output", type=Path)
    output.add_argument("--output-dir", type=Path, default=Path("logs"))
    p.add_argument("--format", choices=("pcapng", "pcap"))
    p.add_argument("--rotate-seconds", type=float)
    p.add_argument("--rotate-size-mb", type=float, help="decimal MB (1,000,000 bytes)")
    p.add_argument("--buffer-mb", type=int, default=64, help="capture buffer in MiB (default 64)")
    p.add_argument("--promiscuous", action="store_true", help="request promiscuous mode (default off)")
    p.add_argument("--min-free-gb", type=float, default=10, help="stop below this free space in GiB (default 10)")
    p.add_argument("--duration", type=float, help="optional capture duration in seconds")
    p.add_argument("--dumpcap", default="dumpcap", help="dumpcap executable path")
    a = p.parse_args(argv)
    a.format = a.format or (a.output.suffix.lower().lstrip(".") if a.output else "pcapng")
    config = Config(**vars(a))
    try:
        config.validate()
    except ValueError as exc:
        p.error(str(exc))
    return config
