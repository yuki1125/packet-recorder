"""Read interface information without changing host configuration."""
import argparse
import json
import re
import socket
import subprocess
import sys
from .backend import quiet_options, resolve_dumpcap


def list_interfaces(dumpcap="dumpcap"):
    if sys.platform == "win32":
        return windows_interfaces(resolve_dumpcap(dumpcap))
    if sys.platform != "linux":
        raise ValueError("supported platforms: Linux and Windows")
    result = subprocess.run(["ip", "-j", "address", "show"], check=True,
                            capture_output=True, text=True, timeout=10)
    return [{"name": i["ifname"], "mac": i.get("address"),
             "ipv4": [a["local"] for a in i.get("addr_info", [])
                      if a["family"] == "inet"],
             "link_state": i.get("operstate", "UNKNOWN"),
             "link_type": i.get("link_type", "unknown")}
            for i in json.loads(result.stdout)]


def windows_adapter_details():
    # Fixed read-only script; interface names are matched in Python, never interpolated.
    script = """
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)
$items = @(Get-NetAdapter -IncludeHidden | ForEach-Object {
    [pscustomobject]@{ guid = $_.InterfaceGuid.ToString(); name = $_.Name;
        index = $_.ifIndex; mac = $_.MacAddress; state = $_.Status.ToString();
        ipv4 = @($addresses | Where-Object InterfaceIndex -EQ $_.ifIndex | Select-Object -ExpandProperty IPAddress) }
})
ConvertTo-Json -InputObject $items -Depth 4 -Compress
"""
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, encoding="utf-8-sig", errors="replace",
                            check=True, timeout=10, **quiet_options())
    return json.loads(result.stdout)


def parse_windows_interfaces(text, details):
    by_guid = {a["guid"].strip("{}").casefold(): a for a in details}
    interfaces = []
    for line in text.splitlines():
        match = re.match(r"^(\d+)\.\s+(\\Device\\NPF_\{([0-9A-Fa-f-]+)\})(?:\s+\((.*)\))?\s*$", line)
        if not match:
            continue
        index, device, guid, description = match.groups()
        adapter = by_guid.get(guid.casefold(), {})
        interfaces.append({"name": device, "capture_index": int(index),
            "display_name": adapter.get("name") or description or device,
            "mac": adapter.get("mac"), "ipv4": adapter.get("ipv4") or [],
            "link_state": adapter.get("state", "UNKNOWN"), "link_type": "ether_candidate",
            "os_index": adapter.get("index")})
    return interfaces


def windows_interfaces(dumpcap):
    result = subprocess.run([dumpcap, "-D"], capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=10, **quiet_options())
    if result.returncode:
        raise ValueError("Cannot enumerate capture devices. Check Wireshark/Npcap installation and "
                         "capture permissions. " + result.stderr.strip())
    try:
        details = windows_adapter_details()
    except (OSError, ValueError, subprocess.SubprocessError):
        details = []  # capture IDs from dumpcap remain usable if OS metadata is unavailable
    return parse_windows_interfaces(result.stdout, details)


def select_interface(items, value):
    if sys.platform != "win32":
        matches = [i for i in items if i["name"] == value and i["link_type"] == "ether"]
    else:
        # A capture ID is authoritative; friendly names and temporary dumpcap numbers are aliases.
        matches = [i for i in items if i["name"].casefold() == value.casefold()]
        if not matches:
            matches = [i for i in items if str(i["capture_index"]) == value
                       or i["display_name"].casefold() == value.casefold()]
    if len(matches) != 1:
        raise ValueError("Select one unambiguous Ethernet interface from: python -m packet_recorder.interfaces")
    return matches[0]


def interface_present(info):
    entries = socket.if_nameindex()
    if sys.platform == "win32":
        index = info.get("os_index")
        return index is None or index in {i for i, _ in entries}
    return info["name"] in {name for _, name in entries}


def main(argv=None):
    parser = argparse.ArgumentParser(description="List Ethernet capture interfaces")
    parser.add_argument("--dumpcap", default="dumpcap", help="dumpcap executable path")
    args = parser.parse_args(argv)
    try:
        items = list_interfaces(args.dumpcap)
        if not items:
            raise ValueError("No Ethernet capture interfaces found; on Windows check Npcap installation")
        print("INTERFACE\tNAME\tMAC\tIPv4\tSTATE")
        for i in items:
            print("\t".join([i["name"], i.get("display_name", i["name"]), i["mac"] or "-",
                             ",".join(i["ipv4"]) or "-", i["link_state"]]))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Cannot list interfaces: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
