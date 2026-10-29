"""Network evidence only: no account credentials or anti-ban predictions."""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path


def describe_http_status(code: int) -> tuple[str, str]:
    if code == 407:
        return "proxy_authentication_required", "Прокси требует авторизацию. Это не ответ о состоянии аккаунта Claude."
    if code == 401:
        return "authentication_required", "Требуется авторизация; состояние аккаунта не проверено."
    if code == 403:
        return "access_denied", "Доступ отклонён: возможны фильтр, региональные правила или WAF. Это не доказательство блокировки аккаунта."
    if code == 429:
        return "rate_limited", "Ограничение частоты запросов. Повторите проверку позднее."
    if 500 <= code <= 599:
        return "server_error", "Ошибка сервера или промежуточного прокси. Сверьтесь со страницей состояния сервиса."
    if 200 <= code <= 299:
        return "response_received", "Получен ответ сайта; доступ к аккаунту не проверен."
    return "http_error", "Получен HTTP-ответ; работоспособность сервиса и аккаунта не подтверждена."


def check_https(url: str, timeout: float = 7) -> dict:
    started = time.monotonic()
    result = {"name": f"HTTPS: {url}", "kind": "https", "ok": False,
              "http_status": None, "proxy_status": None, "status": "connection_error"}
    request = urllib.request.Request(
        url, headers={"User-Agent": "obman/0.3 network-diagnostic"}, method="GET"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            result["http_status"] = response.getcode()
    except urllib.error.HTTPError as exc:
        result["http_status"] = exc.code
        exc.close()
    except (TimeoutError, urllib.error.URLError, OSError) as exc:
        reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
        tunnel_error = re.match(r"^Tunnel connection failed: (403|407)\b", str(reason))
        if tunnel_error:
            code = int(tunnel_error.group(1))
            result["proxy_status"] = code
            if code == 407:
                result.update(status="proxy_authentication_required", detail="Прокси отклонил CONNECT: HTTP 407, требуется авторизация прокси.")
            else:
                result.update(status="proxy_access_denied", detail="Прокси отклонил CONNECT: HTTP 403. Ответ от Claude не получен.")
        elif isinstance(reason, ssl.SSLError):
            result.update(status="tls_error", detail="Ошибка проверки TLS. Проверьте сертификаты и системное время.")
        elif isinstance(reason, (TimeoutError, socket.timeout)):
            result.update(status="timeout", detail="Истекло время ожидания соединения.")
        elif isinstance(reason, socket.gaierror):
            result.update(status="dns_error", detail="Не удалось разрешить имя узла.")
        else:
            # Exception text can contain credentials from a configured proxy URL.
            result["detail"] = "Не удалось установить соединение. Проверьте сеть и настройки прокси."
    if result["http_status"] is not None:
        result["ok"] = result["http_status"] != 407
        result["status"], explanation = describe_http_status(result["http_status"])
        result["detail"] = f"HTTP {result['http_status']}. {explanation}"
    result["duration_ms"] = round((time.monotonic() - started) * 1000)
    return result


def environment_snapshot(environ=None, proxies=None) -> dict:
    """Record names/presence only. Never retain proxy URLs, tokens or endpoint values."""
    environ = os.environ if environ is None else environ
    proxies = urllib.request.getproxies() if proxies is None else proxies
    names = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
             "http_proxy", "https_proxy", "all_proxy", "no_proxy",
             "ANTHROPIC_BASE_URL", "CLAUDE_CODE_USE_BEDROCK",
             "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY")
    return {
        "variables_present": {name: bool(environ.get(name)) for name in names},
        "python_proxy_configured": {name: bool(proxies.get(name))
                                    for name in ("http", "https", "all", "no")},
        "scope": "Только текущий процесс Python. Claude Code, Desktop, WSL и браузер могут использовать другие настройки.",
        "route_verified": False,
    }


def main():
    parser = argparse.ArgumentParser(description="Диагностика из того же терминала/WSL, где запускается Claude Code.")
    parser.add_argument("--check-network", action="store_true", help="Выполнить HTTPS GET к claude.ai и api.anthropic.com без ключей и авторизации")
    parser.add_argument("--output", type=Path, help="Сохранить новый JSON-файл (существующие файлы не перезаписываются)")
    args = parser.parse_args()
    report = {"timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
              "environment": environment_snapshot(), "checks": []}
    if args.check_network:
        report["checks"] = [check_https(url) for url in
                            ("https://claude.ai/", "https://api.anthropic.com/")]
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        with args.output.open("x", encoding="utf-8") as output:
            output.write(text + "\n")
    else:
        print(text)
    if args.check_network and any(not row["ok"] or row["status"] != "response_received"
                                  for row in report["checks"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
