"""Platform-specific executable discovery and capture process lifecycle."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys


def resolve_dumpcap(value="dumpcap"):
    found = shutil.which(value)
    if found:
        return found
    if sys.platform == "win32" and value in ("dumpcap", "dumpcap.exe"):
        for variable in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
            root = os.environ.get(variable)
            if root:
                candidate = Path(root) / "Wireshark" / "dumpcap.exe"
                if candidate.is_file():
                    return str(candidate)
        raise FileNotFoundError("dumpcap.exe not found. Install Wireshark with Npcap, or pass --dumpcap PATH")
    raise FileNotFoundError(f"dumpcap executable not found: {value}")


def quiet_options():
    return {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}


def capture_process_options():
    if sys.platform != "win32":
        return {"start_new_session": True}
    # Own console isolates shutdown from the user's PowerShell and other recorders.
    # Keep it hidden, including when Recorder is launched by an IDE/background job.
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = subprocess.SW_HIDE
    return {"creationflags": subprocess.CREATE_NEW_CONSOLE, "startupinfo": startup}


def stop_process(process, timeout=10):
    if process.poll() is not None:
        return False
    try:
        if sys.platform == "win32":
            helper = Path(__file__).with_name("_windows_signal.py")
            subprocess.run([sys.executable, str(helper), str(process.pid)], check=True,
                           capture_output=True, timeout=3, **quiet_options())
        else:
            process.send_signal(signal.SIGINT)
        process.wait(timeout=timeout)
        return False
    except ProcessLookupError:
        return False
    except (OSError, subprocess.SubprocessError):
        if process.poll() is not None:
            return False
        process.kill()
        process.wait()
        return True
