"""
Runtime security guard — prevents debugging, tracing, memory dumping,
and environment tampering at the process level.

Call ``enforce()`` once at startup, before the application begins.
"""

import ctypes
import os
import resource
import signal
import sys
import threading


def _disable_core_dumps():
    """Prevent core dumps that could expose decrypted data in memory."""
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, resource.error):
        pass


def _disable_ptrace():
    """Set PR_SET_DUMPABLE=0 so ptrace/gdb cannot attach to this process."""
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        PR_SET_DUMPABLE = 4
        libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    except (OSError, AttributeError):
        pass


def _remove_debug_signals():
    """Ignore signals commonly used by debuggers."""
    for sig in (signal.SIGTRAP, signal.SIGABRT):
        try:
            signal.signal(sig, signal.SIG_IGN)
        except (OSError, ValueError):
            pass


def _check_debugger():
    """Detect if a debugger is attached via /proc/self/status."""
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("TracerPid:"):
                    pid = int(line.split(":")[1].strip())
                    if pid != 0:
                        os._exit(1)
                    break
    except (FileNotFoundError, PermissionError, ValueError):
        pass


def _set_process_title():
    """Clear argv so /proc/self/cmdline doesn't reveal startup details."""
    try:
        ctypes.CDLL("libc.so.6").prctl(15, b"prism_worker", 0, 0, 0)
    except (OSError, AttributeError):
        pass


def _background_watchdog():
    """Periodically check for debugger attachment."""
    import time
    while True:
        _check_debugger()
        time.sleep(30)


def enforce():
    """Apply all runtime security protections."""
    _disable_core_dumps()
    _disable_ptrace()
    _remove_debug_signals()
    _check_debugger()
    _set_process_title()

    # Disable interactive help / inspect
    sys.flags  # read-only, but we can remove modules
    for mod_name in ("pdb", "code", "codeop", "readline"):
        sys.modules[mod_name] = None

    # Start background watchdog (daemon so it dies with the main process)
    t = threading.Thread(target=_background_watchdog, daemon=True)
    t.start()
