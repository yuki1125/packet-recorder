"""Read interface information without changing host configuration."""
import json
import subprocess
import sys


def list_interfaces():
    result = subprocess.run(["ip", "-j", "address", "show"], check=True,
                            capture_output=True, text=True, timeout=10)
    return [{"name": i["ifname"], "mac": i.get("address"),
             "ipv4": [a["local"] for a in i.get("addr_info", [])
                      if a["family"] == "inet"],
             "link_state": i.get("operstate", "UNKNOWN"),
             "link_type": i.get("link_type", "unknown")}
            for i in json.loads(result.stdout)]


def main():
    try:
        print("INTERFACE\tMAC\tIPv4\tSTATE\tTYPE")
        for i in list_interfaces():
            print("\t".join([i["name"], i["mac"] or "-",
                             ",".join(i["ipv4"]) or "-", i["link_state"], i["link_type"]]))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Cannot list Linux interfaces: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
