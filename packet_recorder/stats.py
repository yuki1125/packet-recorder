"""Post-capture container accounting. No protocol decoding, no live packet path."""
import re
import struct
from fractions import Fraction


def exact(stream, count):
    data = stream.read(count)
    if len(data) != count:
        raise ValueError("truncated capture file")
    return data


def options(raw, endian):
    pos = 0
    while pos + 4 <= len(raw):
        code, length = struct.unpack_from(endian + "HH", raw, pos)
        pos += 4
        if code == 0:
            break
        if pos + length > len(raw):
            raise ValueError("truncated PCAPNG option")
        yield code, raw[pos:pos + length]
        pos += (length + 3) & ~3


def scan_capture(path):
    result = {"path": str(path), "packets": 0, "captured_bytes": 0,
              "truncated_packets": 0, "file_bytes": path.stat().st_size,
              "interfaces": [], "interface_statistics": [],
              "first_timestamp": None, "last_timestamp": None}

    def packet(caplen, wirelen, timestamp):
        if caplen > wirelen:
            raise ValueError("captured length exceeds original length")
        result["packets"] += 1
        result["captured_bytes"] += caplen
        result["truncated_packets"] += caplen < wirelen
        if timestamp is not None:
            # Rational seconds retain the original precision, including binary resolutions.
            value = str(timestamp)
            if result["first_timestamp"] is None:
                result["first_timestamp"] = value
            result["last_timestamp"] = value

    with path.open("rb") as f:
        magic = exact(f, 4)
        f.seek(0)
        formats = {b"\xd4\xc3\xb2\xa1": ("<", 10**6), b"\xa1\xb2\xc3\xd4": (">", 10**6),
                   b"\x4d\x3c\xb2\xa1": ("<", 10**9), b"\xa1\xb2\x3c\x4d": (">", 10**9)}
        if magic in formats:
            endian, scale = formats[magic]
            header = exact(f, 24)
            snaplen, link = struct.unpack_from(endian + "II", header, 16)
            result["interfaces"].append({"link_type": link & 0xffff, "snaplen": snaplen,
                                         "timestamp_resolution": f"1/{scale}"})
            while head := f.read(16):
                if len(head) != 16:
                    raise ValueError("truncated PCAP record")
                sec, sub, cap, wire = struct.unpack(endian + "IIII", head)
                if cap > snaplen or sub >= scale:
                    raise ValueError("invalid PCAP record")
                if f.tell() + cap > result["file_bytes"]:
                    raise ValueError("truncated PCAP payload")
                f.seek(cap, 1)
                packet(cap, wire, Fraction(sec) + Fraction(sub, scale))
        elif magic == b"\x0a\x0d\x0d\x0a":
            endian = "<"
            interfaces = []
            while head := f.read(8):
                if len(head) != 8:
                    raise ValueError("truncated PCAPNG block")
                if head[:4] == magic:
                    bom = exact(f, 4)
                    if bom not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                        raise ValueError("invalid PCAPNG byte order")
                    endian = "<" if bom[0] == 0x4d else ">"
                    f.seek(-4, 1)
                    interfaces = []
                kind, length = struct.unpack(endian + "II", head)
                if length < 12 or length % 4 or length > 32 * 1024 * 1024:
                    raise ValueError("invalid or oversized PCAPNG block")
                body = exact(f, length - 12)
                if struct.unpack(endian + "I", exact(f, 4))[0] != length:
                    raise ValueError("PCAPNG block length mismatch")
                if kind == 1:
                    link, _, snap = struct.unpack_from(endian + "HHI", body)
                    info = {"link_type": link, "snaplen": snap,
                            "timestamp_resolution": "1/1000000", "timestamp_offset": 0}
                    for code, value in options(body[8:], endian):
                        if code == 2:
                            info["name"] = value.decode("utf-8", "replace")
                        elif code == 9 and len(value) == 1:
                            v = value[0]
                            info["timestamp_resolution"] = str(Fraction(1, 2**(v & 127) if v & 128 else 10**v))
                        elif code == 14 and len(value) == 8:
                            info["timestamp_offset"] = struct.unpack(endian + "q", value)[0]
                    interfaces.append(info)
                    result["interfaces"].append(info)
                elif kind == 6:
                    idx, high, low, cap, wire = struct.unpack_from(endian + "IIIII", body)
                    if idx >= len(interfaces) or 20 + ((cap + 3) & ~3) > len(body):
                        raise ValueError("invalid PCAPNG packet")
                    info = interfaces[idx]
                    ts = ((high << 32) | low) * Fraction(info["timestamp_resolution"]) + info["timestamp_offset"]
                    packet(cap, wire, ts)
                elif kind == 5:
                    idx, _, _ = struct.unpack_from(endian + "III", body)
                    record = {"interface_id": idx}
                    names = {4: "ifrecv", 5: "ifdrop", 6: "filteraccept", 7: "osdrop", 8: "usrdeliv"}
                    for code, value in options(body[12:], endian):
                        if code in names and len(value) == 8:
                            record[names[code]] = struct.unpack(endian + "Q", value)[0]
                    result["interface_statistics"].append(record)
                elif kind in (2, 3):
                    raise ValueError("legacy PCAPNG packet blocks not generated by supported dumpcap")
        else:
            raise ValueError("unknown capture format")
    return result


def parse_dumpcap_statistics(text):
    result = {"dumpcap_packets": None, "kernel_drops": None, "capture_drops": None}
    counts = re.findall(r"Packets captured:\s*(\d+)", text)
    if counts:
        result["dumpcap_packets"] = int(counts[-1])
    # Modern dumpcap identifies pcap_stats.ps_drop explicitly in its final breakdown.
    kernel = re.findall(r"\bpcap:\s*(\d+)", text)
    capture = re.findall(r"\bdumpcap:\s*(\d+)", text)
    if kernel:
        result["kernel_drops"] = int(kernel[-1])
    if capture:
        result["capture_drops"] = int(capture[-1])
    for label, key in (("flushed", "flushed_drops"), ("ps_ifdrop", "reported_interface_drops")):
        values = re.findall(r"\b" + label + r":\s*(\d+)", text)
        result[key] = int(values[-1]) if values else None
    return result
