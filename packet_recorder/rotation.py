"""Naming and native dumpcap rotation; never a bounded overwrite ring."""
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
import math


def output_path(config):
    if config.output:
        return config.output.absolute()
    now = datetime.now(timezone.utc)
    return (config.output_dir / now.strftime("%Y%m%d") /
            f"capture_{now:%H%M%S}_{uuid4().hex[:12]}.{config.format}").absolute()


def rotation_args(config):
    args = []
    if config.rotate_seconds:
        args += ["-b", f"duration:{config.rotate_seconds:g}"]
    if config.rotate_size_mb:
        args += ["-b", f"filesize:{math.ceil(config.rotate_size_mb * 1000)}"]
    return args


def capture_files(base: Path, rotating: bool):
    if not rotating:
        return [base] if base.is_file() else []
    # dumpcap appends a sequence and timestamp to the supplied basename.
    return sorted(p for p in base.parent.iterdir()
                  if p.is_file() and p.name.startswith(base.stem + "_")
                  and p.suffix == base.suffix)
