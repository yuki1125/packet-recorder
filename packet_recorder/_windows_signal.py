"""Deliver CTRL_BREAK to the private console of our own capture child.

Executed in a short-lived helper so the supervisor never detaches its console.
"""
import ctypes
from ctypes import wintypes
import sys
import time


def main(pid):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
    kernel.AttachConsole.argtypes = [wintypes.DWORD]
    kernel.AttachConsole.restype = wintypes.BOOL
    kernel.SetConsoleCtrlHandler.argtypes = [callback_type, wintypes.BOOL]
    kernel.SetConsoleCtrlHandler.restype = wintypes.BOOL
    kernel.GenerateConsoleCtrlEvent.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.GenerateConsoleCtrlEvent.restype = wintypes.BOOL
    kernel.FreeConsole()
    if not kernel.AttachConsole(pid):
        raise ctypes.WinError(ctypes.get_last_error())
    handler = callback_type(lambda event: True)
    try:
        if not kernel.SetConsoleCtrlHandler(handler, True):
            raise ctypes.WinError(ctypes.get_last_error())
        # This console belongs only to dumpcap and this helper, never the user's shell.
        if not kernel.GenerateConsoleCtrlEvent(1, 0):  # CTRL_BREAK_EVENT
            raise ctypes.WinError(ctypes.get_last_error())
        time.sleep(0.1)  # allow asynchronous handler delivery before detaching
    finally:
        kernel.FreeConsole()


if __name__ == "__main__":
    main(int(sys.argv[1]))
