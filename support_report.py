"""Minimal export: excludes DNS addresses, free text, process lists and event logs."""
from datetime import datetime

from network_diagnostics import environment_snapshot

CHECK_NAMES = {f"{kind}: {host}" for kind in ("DNS", "HTTPS")
               for host in ("claude.ai", "www.anthropic.com")}
CHECK_NAMES |= {"HTTPS: https://claude.ai/", "HTTPS: https://www.anthropic.com/"}
STATUSES = {"response_received", "authentication_required", "access_denied", "rate_limited",
            "server_error", "http_error", "connection_error", "tls_error", "timeout", "dns_error",
            "proxy_authentication_required", "proxy_access_denied"}


def safe_checks(results):
    checks = []
    for row in results:
        if row.get("name") not in CHECK_NAMES or row.get("kind") not in ("dns", "https"):
            continue
        item = {"name": row["name"], "kind": row["kind"], "ok": row.get("ok") is True}
        if row.get("status") in STATUSES:
            item["status"] = row["status"]
        for key in ("http_status", "proxy_status", "duration_ms"):
            value = row.get(key)
            if type(value) is int and value >= 0:
                item[key] = value
        checks.append(item)
    return checks


def compare_runs(current, previous):
    """Compare matching checks by their outcome, ignoring latency and DNS address text."""
    old = {r["name"]: r for r in safe_checks(previous["results"])}
    new = {r["name"]: r for r in safe_checks(current["results"])}
    changes = []
    keys = ("ok", "status", "http_status", "proxy_status")
    for name in sorted(old.keys() | new.keys()):
        before, after = old.get(name), new.get(name)
        if before is None or after is None or any(before.get(k) != after.get(k) for k in keys):
            changes.append({"name": name, "before": before, "after": after})
    return changes


def build_support_report(run, version, previous=None):
    environment = run.get("environment") or {}
    template = environment_snapshot({}, {})
    presence = {}
    for group in ("variables_present", "python_proxy_configured"):
        values = environment.get(group, {})
        presence[group] = {key: value for key, value in values.items()
                           if key in template[group] and type(value) is bool}
    return {
        "schema_version": 1,
        "app_version": version,
        "exported_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "run_timestamp": run["timestamp"],
        "connectivity_score": run["score"],
        "checks": safe_checks(run["results"]),
        "environment": presence if environment else None,
        "changes_since_previous": compare_runs(run, previous) if previous else None,
        "limitations": "Проверки процесса obman, не статус аккаунта и не доказательство маршрута VPN. "
                        "Отчёт не содержит IP из DNS, значений переменных, заметок Net.Coffee и журнала событий.",
    }
