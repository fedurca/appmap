"""Windows platform backend (standard library only: ctypes / winreg / socket /
subprocess to built-in tools). Modules import cleanly on non-Windows too;
``windll``/``winreg`` are only touched at call time and every entry point is
``available()``-gated so the tool degrades gracefully."""
