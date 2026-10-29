"""Read-only Windows evidence. Never claims to verify Claude's traffic route."""
from __future__ import annotations

import csv
import ipaddress
import json
import os
import subprocess
from urllib.parse import urlsplit


def is_loopback_proxy(value: str) -> bool:
    for entry in value.split(";"):
        address = entry.split("=", 1)[-1].strip()
        try:
            parsed = urlsplit(address if "://" in address else "http://" + address)
            if parsed.username or parsed.password or not parsed.port:
                continue
            host = parsed.hostname or ""
            if host.lower() == "localhost" or ipaddress.ip_address(host).is_loopback:
                return True
        except ValueError:
            continue
    return False


def read_proxy_settings():
    import winreg

    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
        def read(name, default):
            try:
                return winreg.QueryValueEx(key, name)[0]
            except FileNotFoundError:
                return default
        enabled = bool(read("ProxyEnable", 0))
        server = read("ProxyServer", "")
        return {"enabled": enabled, "local_proxy_configured": enabled and is_loopback_proxy(str(server)),
                "pac_configured": bool(read("AutoConfigURL", ""))}


def run_command(args):
    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=8,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        raise OSError("Windows probe failed")
    return result.stdout


def read_processes():
    output = run_command(["tasklist", "/FO", "CSV", "/NH"])
    return any(row and row[0].casefold() in {"happ.exe", "happ-desktop.exe"}
               for row in csv.reader(output.splitlines()))


def read_tunnel_candidates():
    # Return only a count, never adapter names, IPs or full PowerShell errors.
    script = ("$ErrorActionPreference='Stop'; "
              "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); "
              "$n=@(Get-NetAdapter -IncludeHidden | Where-Object { "
              "$_.Status -eq 'Up' -and "
              "($_.Name -match 'happ|wintun|tun2socks' -or "
              "$_.InterfaceDescription -match 'happ|wintun|tun2socks') }).Count; "
              "ConvertTo-Json -Compress -InputObject $n")
    count = json.loads(run_command(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script]))
    if type(count) is not int or count < 0:
        raise ValueError("Invalid adapter count")
    return count


def classify_evidence(running, proxy, tunnels):
    mode = "unknown"
    if running is True and proxy is not None and tunnels is not None:
        has_proxy = proxy["enabled"] or proxy["pac_configured"]
        if has_proxy and tunnels:
            mode = "mixed_candidate"
        elif has_proxy:
            mode = "proxy_candidate"
        elif tunnels:
            mode = "tun_candidate"
    labels = {
        "unknown": "Режим Happ не определён",
        "proxy_candidate": "Возможен режим системного прокси",
        "tun_candidate": "Обнаружены признаки TUN-подключения",
        "mixed_candidate": "Есть признаки и прокси, и TUN — режим неоднозначен",
    }
    return {"mode": mode, "summary": labels[mode], "happ_running": running,
            "windows_proxy": proxy, "active_tunnel_candidates": tunnels,
            "route_verified": False,
            "limitation": "Прокси или адаптер могут принадлежать другой программе. Маршрут Claude Desktop не подтверждён."}


def detect_happ():
    if os.name != "nt":
        result = classify_evidence(None, None, None)
        result["summary"] = "Автоопределение Happ доступно на Windows"
        return result
    observations = []
    for probe in (read_processes, read_proxy_settings, read_tunnel_candidates):
        try:
            observations.append(probe())
        except (OSError, ValueError, TypeError, subprocess.SubprocessError):
            observations.append(None)
    return classify_evidence(*observations)


if __name__ == "__main__":
    print(json.dumps(detect_happ(), ensure_ascii=False, indent=2))
