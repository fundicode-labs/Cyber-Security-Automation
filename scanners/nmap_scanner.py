"""Nmap integration helpers."""

import os
import shutil
import subprocess


def _resolve_nmap_binary():
    binary = shutil.which("nmap")
    if binary:
        return binary

    # Common Windows install locations when PATH has not been refreshed yet.
    windows_candidates = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ]
    for candidate in windows_candidates:
        if os.path.isfile(candidate):
            return candidate

    return None


def run_nmap_scan(target, arguments=None):
    if arguments is None:
        arguments = ["-Pn", "-sV", "--top-ports", "50"]

    nmap_binary = _resolve_nmap_binary()
    if nmap_binary:
        command = [nmap_binary, *arguments, target]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        return {
            "engine": "nmap",
            "command": " ".join(command),
            "returncode": completed.returncode,
            "output": completed.stdout.strip() or completed.stderr.strip(),
        }

    return {
        "engine": "fallback",
        "command": "nmap not installed",
        "returncode": 0,
        "output": f"Nmap is not installed. Use the built-in scanner result for {target}.",
    }