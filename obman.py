from __future__ import annotations

import json
import ipaddress
import os
import platform
import queue
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from network_diagnostics import check_https, environment_snapshot
from support_report import build_support_report, compare_runs
from happ_detection import detect_happ

APP_NAME = "obman"
APP_VERSION = "0.5.0-dev"
CLAUDE_URL = "https://claude.ai/"
ANTHROPIC_URL = "https://www.anthropic.com/"
NET_COFFEE_URL = "https://ip.net.coffee/claude"
DB_PATH = Path(os.environ.get("APPDATA", str(Path.home()))) / "obman" / "obman.db"


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def check_dns(host: str, port: int = 443) -> dict:
    started = time.monotonic()
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses = sorted({row[4][0] for row in records})
        return {
            "name": f"DNS: {host}",
            "ok": bool(addresses),
            "detail": ", ".join(addresses[:4]) if addresses else "Адреса не найдены",
            "duration_ms": round((time.monotonic() - started) * 1000),
        }
    except OSError as exc:
        return {
            "name": f"DNS: {host}", "ok": False,
            "detail": f"{type(exc).__name__}: {exc}",
            "duration_ms": round((time.monotonic() - started) * 1000),
        }


def get_running_processes() -> tuple[list[str], str]:
    """Best-effort process listing; does not inspect command-line arguments."""
    names = {
        "claude.exe", "claude", "claude code", "claude-desktop.exe",
        "claude desktop.exe", "claude_desktop.exe", "claude-code.exe",
        "v2rayn.exe", "sing-box.exe", "sing-box", "xray.exe",
    }
    try:
        if os.name == "nt":
            result = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=5, errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode != 0:
                return [], f"tasklist завершился с кодом {result.returncode}"
            found = []
            for line in result.stdout.splitlines():
                # tasklist CSV format: "Image Name","PID",...
                first = line.split('","', 1)[0].strip('"').lower()
                if first in names or any(k in first for k in ("claude", "v2rayn", "sing-box")):
                    found.append(line.strip().strip('"'))
            return found, "Список процессов получен через tasklist"
        # Non-Windows fallback for development.
        result = subprocess.run(
            ["ps", "-A", "-o", "comm="],
            capture_output=True, text=True, timeout=5, errors="replace",
        )
        found = [line.strip() for line in result.stdout.splitlines()
                 if any(k in line.lower() for k in ("claude", "v2rayn", "sing-box"))]
        return found, "Список процессов получен через ps (для разработки)"
    except Exception as exc:
        return [], f"Не удалось получить список процессов: {exc}"


class Store:
    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    category TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT NOT NULL,
                    details TEXT NOT NULL DEFAULT ''
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS coffee_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    region TEXT NOT NULL,
                    trust_score INTEGER,
                    notes TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    summary TEXT NOT NULL,
                    results_json TEXT NOT NULL
                )
            """)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(runs)")}
            if "environment_json" not in columns:
                conn.execute("ALTER TABLE runs ADD COLUMN environment_json TEXT NOT NULL DEFAULT '{}'")

    def event(self, category: str, status: str, message: str, details: str = ""):
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO events(timestamp,category,status,message,details) VALUES(?,?,?,?,?)",
                (now_iso(), category, status, message, details),
            )

    def save_run(self, score: int, summary: str, results: list[dict], environment=None):
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO runs(timestamp,score,summary,results_json,environment_json) VALUES(?,?,?,?,?)",
                (now_iso(), score, summary, json.dumps(results, ensure_ascii=False),
                 json.dumps(environment or {}, ensure_ascii=False)),
            )

    def recent_runs(self, limit=200):
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                "SELECT id,timestamp,score,summary,results_json,environment_json FROM runs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(id=r[0], timestamp=r[1], score=r[2], summary=r[3],
                     results=json.loads(r[4]), environment=json.loads(r[5])) for r in rows]

    def recent_events(self, limit: int = 200):
        with sqlite3.connect(self.path) as conn:
            return conn.execute(
                "SELECT timestamp,category,status,message,details FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()

    def save_coffee_report(self, ip: str, region: str, trust_score: str, notes: str):
        ip = str(ipaddress.ip_address(ip.strip()))
        score_text = trust_score.strip()
        score = int(score_text) if score_text else None
        if score is not None and not 0 <= score <= 100:
            raise ValueError("Trust Score должен быть целым числом от 0 до 100.")
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO coffee_reports(timestamp,ip,region,trust_score,notes) VALUES(?,?,?,?,?)",
                (now_iso(), ip, region.strip(), score, notes.strip()),
            )

    def recent_coffee_reports(self, limit: int = 200):
        with sqlite3.connect(self.path) as conn:
            return conn.execute(
                "SELECT timestamp,ip,region,trust_score,notes FROM coffee_reports ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()


def calculate_network_score(results: list[dict]) -> tuple[int, str]:
    """
    Explainable local connectivity score, NOT an Anthropic account/risk score.
    Only scores the four basic DNS/HTTPS checks in this MVP.
    """
    relevant = [r for r in results if r.get("kind") in ("dns", "https")]
    if not relevant:
        return 0, "Нет результатов проверки"
    passed = sum(1 for r in relevant if r.get("ok"))
    score = round(100 * passed / len(relevant))
    return score, f"Успешно {passed} из {len(relevant)} проверок доступности"


class ObmanApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"obman — диагностика Claude ({APP_VERSION})")
        self.geometry("980x700")
        self.minsize(800, 560)
        self.store = Store()
        self.events_queue = queue.Queue()
        self._build_ui()
        self._refresh_events()
        self.store.event("app", "INFO", f"Приложение запущено, версия {APP_VERSION}")
        self.after(150, self._drain_queue)
        self.happ_detection_running = False
        self.after(300, self.refresh_happ)

    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("vista" if os.name == "nt" else "clam")
        except tk.TclError:
            pass
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("Sub.TLabel", font=("Segoe UI", 9))
        style.configure("Score.TLabel", font=("Segoe UI", 22, "bold"))
        root = ttk.Frame(self, padding=14)
        root.pack(fill="both", expand=True)

        header = ttk.Frame(root)
        header.pack(fill="x")
        ttk.Label(header, text="obman", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="MVP 0.5 · локальная диагностика соединения", style="Sub.TLabel").pack(side="left", padx=12, pady=(5, 0))
        ttk.Button(header, text="Открыть Net.Coffee", command=self.open_net_coffee).pack(side="right")
        ttk.Label(
            root,
            text="Проверяем техническую доступность сети. Это не прогноз блокировки и не оценка аккаунта Anthropic.",
            wraplength=900,
        ).pack(anchor="w", pady=(8, 12))

        happ_frame = ttk.LabelFrame(root, text="Happ — автоопределение", padding=8)
        happ_frame.pack(fill="x", pady=(0, 8))
        self.happ_label = ttk.Label(happ_frame, text="Проверка ещё не выполнена", wraplength=750)
        self.happ_label.pack(side="left", fill="x", expand=True)
        self.happ_button = ttk.Button(happ_frame, text="Проверить Happ", command=self.refresh_happ)
        self.happ_button.pack(side="right")

        actions = ttk.Frame(root)
        actions.pack(fill="x", pady=(0, 10))
        self.check_button = ttk.Button(actions, text="Запустить диагностику", command=self.run_diagnostics)
        self.check_button.pack(side="left")
        ttk.Button(actions, text="Проверить процессы", command=self.check_processes).pack(side="left", padx=8)
        ttk.Button(actions, text="Среда / прокси", command=self.show_environment).pack(side="left")
        ttk.Button(actions, text="Обновить журнал", command=self._refresh_events).pack(side="left", padx=8)
        ttk.Button(actions, text="Экспорт журнала…", command=self.export_events).pack(side="right")

        score_frame = ttk.LabelFrame(root, text="Индекс сетевой доступности", padding=10)
        score_frame.pack(fill="x", pady=(0, 10))
        self.score_label = ttk.Label(score_frame, text="—", style="Score.TLabel")
        self.score_label.pack(side="left", padx=(0, 18))
        self.score_text = ttk.Label(score_frame, text="Запустите диагностику, чтобы получить результат.", wraplength=730)
        self.score_text.pack(side="left", fill="x", expand=True)

        tabs = ttk.Notebook(root)
        tabs.pack(fill="both", expand=True)
        diag_tab = ttk.Frame(tabs, padding=8)
        log_tab = ttk.Frame(tabs, padding=8)
        notes_tab = ttk.Frame(tabs, padding=12)
        coffee_tab = ttk.Frame(tabs, padding=12)
        history_tab = ttk.Frame(tabs, padding=12)
        tabs.add(diag_tab, text="Результаты")
        tabs.add(coffee_tab, text="Проверка IP и сети")
        tabs.add(history_tab, text="История и отчёт")
        tabs.add(log_tab, text="Журнал событий")
        tabs.add(notes_tab, text="VPN и ограничения")
        self._build_coffee_tab(coffee_tab)
        self._build_history_tab(history_tab)

        columns = ("status", "name", "detail", "duration")
        self.results_tree = ttk.Treeview(diag_tab, columns=columns, show="headings", height=12)
        for col, label in (("status", "Статус"), ("name", "Проверка"), ("detail", "Результат"), ("duration", "мс")):
            self.results_tree.heading(col, text=label)
        self.results_tree.column("status", width=82, anchor="center")
        self.results_tree.column("name", width=190)
        self.results_tree.column("detail", width=520)
        self.results_tree.column("duration", width=70, anchor="e")
        yscroll = ttk.Scrollbar(diag_tab, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=yscroll.set)
        self.results_tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")

        log_cols = ("timestamp", "category", "status", "message")
        self.log_tree = ttk.Treeview(log_tab, columns=log_cols, show="headings", height=12)
        for col, label, width in (
            ("timestamp", "Время", 170), ("category", "Категория", 100),
            ("status", "Статус", 80), ("message", "Событие", 520),
        ):
            self.log_tree.heading(col, text=label)
            self.log_tree.column(col, width=width)
        log_scroll = ttk.Scrollbar(log_tab, orient="vertical", command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=log_scroll.set)
        self.log_tree.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")

        notes = (
            "Что умеет MVP\n"
            "• Открывает Net.Coffee для проверки IP в браузере.\n"
            "• Проверяет DNS и HTTPS-доступность claude.ai и anthropic.com.\n"
            "• Может показать процессы Claude, v2rayN и sing-box, если они запущены.\n"
            "• Сохраняет результаты и события в локальную SQLite-базу.\n\n"
            "Как читать индекс\n"
            "Это только доля успешных технических проверок. Он не показывает «доверие Anthropic», "
            "не предсказывает бан и не подтверждает доступность аккаунта.\n\n"
            "VPN / split tunneling\n"
            "MVP не меняет конфигурации VPN и системные сетевые настройки. Это намеренно: "
            "автоматическая правка маршрутов без резервной копии может нарушить соединение. "
            "Проверка процессов также не доказывает, через какой маршрут идёт трафик.\n"
            "Кнопка «Среда / прокси» показывает только наличие настроек текущего процесса, без адресов и паролей. "
            "Для проверки из терминала Claude Code используйте network_diagnostics.py.\n\n"
            "Конфиденциальность\n"
            "Диагностика обращается к claude.ai и anthropic.com. Кнопка Net.Coffee открывает "
            "внешний сайт, который может видеть ваш публичный IP и данные браузера. "
            "Приложение не отправляет журнал разработчику; база хранится локально."
        )
        ttk.Label(notes_tab, text=notes, justify="left", wraplength=880).pack(anchor="nw")

        footer = ttk.Label(root, text=f"Журнал: {self.store.path}", style="Sub.TLabel")
        footer.pack(anchor="w", pady=(8, 0))

    def open_net_coffee(self):
        self.store.event("external", "INFO", "Пользователь открыл Net.Coffee", NET_COFFEE_URL)
        self._refresh_events()
        webbrowser.open(NET_COFFEE_URL)

    def _build_coffee_tab(self, tab):
        ttk.Label(tab, text="Скопируйте результаты Net.Coffee вручную. Trust Score — оценка стороннего сайта, "
                  "она не влияет на индекс obman. Проверка браузера не доказывает маршрут Claude Code.",
                  wraplength=850).pack(anchor="w", pady=(0, 10))
        ttk.Button(tab, text="Проверить сеть через Net.Coffee", command=self.open_net_coffee).pack(anchor="w")
        form = ttk.Frame(tab)
        form.pack(fill="x", pady=10)
        self.coffee_fields = {}
        for row, (key, label) in enumerate((("ip", "IP (обязательно)"), ("region", "Страна / регион"),
                                            ("score", "Trust Score 0–100 (необязательно)"),
                                            ("notes", "ASN, провайдер и примечания"))):
            ttk.Label(form, text=label).grid(row=row, column=0, sticky="w", pady=3)
            entry = ttk.Entry(form)
            entry.grid(row=row, column=1, sticky="ew", padx=10)
            self.coffee_fields[key] = entry
        form.columnconfigure(1, weight=1)
        ttk.Button(tab, text="Сохранить результат", command=self.save_coffee_report).pack(anchor="w")
        self.coffee_status = ttk.Label(tab, wraplength=850)
        self.coffee_status.pack(anchor="w", pady=8)
        frame = ttk.Frame(tab)
        frame.pack(fill="both", expand=True)
        columns = ("timestamp", "ip", "region", "score", "notes")
        self.coffee_tree = ttk.Treeview(frame, columns=columns, show="headings", height=5)
        for key, label, width in zip(columns, ("Время", "IP", "Регион", "Trust Score", "Примечания"),
                                     (170, 170, 130, 90, 280)):
            self.coffee_tree.heading(key, text=label)
            self.coffee_tree.column(key, width=width)
        scroll = ttk.Scrollbar(frame, command=self.coffee_tree.yview)
        self.coffee_tree.configure(yscrollcommand=scroll.set)
        self.coffee_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self._refresh_coffee_reports()

    def _refresh_coffee_reports(self):
        for item in self.coffee_tree.get_children():
            self.coffee_tree.delete(item)
        reports = self.store.recent_coffee_reports()
        for row in reports:
            self.coffee_tree.insert("", "end", values=tuple("—" if v is None else v for v in row))
        if len(reports) >= 2:
            changed = [name for index, name in ((1, "IP"), (2, "регион"))
                       if reports[0][index] != reports[1][index]]
            self.coffee_status.configure(text="По сравнению с предыдущей записью: " +
                                         ("изменились " + ", ".join(changed) if changed else "IP и регион совпадают"))
        else:
            self.coffee_status.configure(text="Для сравнения IP и региона сохраните две проверки.")

    def save_coffee_report(self):
        values = {key: entry.get() for key, entry in self.coffee_fields.items()}
        try:
            self.store.save_coffee_report(values["ip"], values["region"], values["score"], values["notes"])
        except ValueError:
            messagebox.showerror("Неверные данные", "Введите корректный IPv4/IPv6 и целый Trust Score от 0 до 100 либо оставьте оценку пустой.")
            return
        except sqlite3.Error as exc:
            messagebox.showerror("Ошибка сохранения", str(exc))
            return
        self._refresh_coffee_reports()

    def _build_history_tab(self, tab):
        ttk.Label(tab, text="Выберите проверку: ниже показаны её результаты и изменения относительно предыдущей записи.",
                  wraplength=850).pack(anchor="w")
        actions = ttk.Frame(tab)
        actions.pack(fill="x", pady=8)
        ttk.Button(actions, text="Обновить историю", command=self._refresh_history).pack(side="left")
        ttk.Button(actions, text="Просмотреть отчёт…", command=self.preview_report).pack(side="right")
        frame = ttk.Frame(tab)
        frame.pack(fill="x")
        self.history_tree = ttk.Treeview(frame, columns=("time", "score", "summary"), show="headings", height=5)
        for key, label, width in (("time", "Время", 190), ("score", "Соединение", 100), ("summary", "Итог", 550)):
            self.history_tree.heading(key, text=label)
            self.history_tree.column(key, width=width)
        scroll = ttk.Scrollbar(frame, command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scroll.set)
        self.history_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.history_tree.bind("<<TreeviewSelect>>", self._show_history_run)
        self.history_detail = tk.Text(tab, height=10, wrap="word", state="disabled")
        self.history_detail.pack(fill="both", expand=True, pady=(8, 0))
        self._refresh_history()

    def _refresh_history(self):
        try:
            runs = self.store.recent_runs(201)
        except (sqlite3.Error, ValueError):
            messagebox.showerror("История", "Не удалось прочитать историю проверок.")
            return
        selected = self.history_tree.selection()
        self.history_runs = runs
        self.history_tree.delete(*self.history_tree.get_children())
        for run in runs[:200]:
            self.history_tree.insert("", "end", iid=str(run["id"]),
                                     values=(run["timestamp"], f"{run['score']}/100", run["summary"]))
        if runs:
            iid = selected[0] if selected and self.history_tree.exists(selected[0]) else str(runs[0]["id"])
            self.history_tree.selection_set(iid)
        self._show_history_run()

    def _selected_history_run(self):
        selected = self.history_tree.selection()
        if selected:
            for index, run in enumerate(self.history_runs):
                if str(run["id"]) == selected[0]:
                    previous = self.history_runs[index + 1] if index + 1 < len(self.history_runs) else None
                    return run, previous
        return None, None

    def _show_history_run(self, event=None):
        run, previous = self._selected_history_run()
        lines = ["Проверок пока нет. Запустите диагностику."]
        if run:
            lines = [run["timestamp"], run["summary"], ""]
            for row in run["results"]:
                lines.append(f"{row['name']}: {row.get('detail', '')}")
            if previous:
                changes = compare_runs(run, previous)
                lines += ["", "Сравнение с " + previous["timestamp"] + ":"]
                lines += [change["name"] + ": изменился результат" for change in changes] or ["Статусы проверок совпадают."]
            else:
                lines += ["", "Предыдущей проверки нет."]
            lines += ["", "Совпадение статусов не подтверждает неизменность IP или маршрута VPN."]
        self.history_detail.configure(state="normal")
        self.history_detail.delete("1.0", "end")
        self.history_detail.insert("1.0", "\n".join(lines))
        self.history_detail.configure(state="disabled")

    def preview_report(self):
        run, previous = self._selected_history_run()
        if not run:
            messagebox.showinfo("Отчёт", "Сначала запустите диагностику и выберите проверку в истории.")
            return
        text = json.dumps(build_support_report(run, APP_VERSION, previous), ensure_ascii=False, indent=2)
        window = tk.Toplevel(self)
        window.title("Отчёт — просмотр перед экспортом")
        window.geometry("850x600")
        ttk.Label(window, text="В файл попадёт ровно текст ниже. Отправка в поддержку не выполняется.").pack(padx=12, pady=8)
        preview = tk.Text(window, wrap="word")
        preview.pack(fill="both", expand=True, padx=12)
        preview.insert("1.0", text)
        preview.configure(state="disabled")

        def save():
            path = filedialog.asksaveasfilename(parent=window, title="Сохранить диагностический отчёт",
                                              defaultextension=".json", initialfile="obman-report.json",
                                              filetypes=[("JSON", "*.json")])
            if not path:
                return
            try:
                Path(path).write_text(text, encoding="utf-8")
            except OSError:
                messagebox.showerror("Отчёт", "Не удалось сохранить файл.", parent=window)
                return
            messagebox.showinfo("Отчёт", "Отчёт сохранён локально.", parent=window)

        ttk.Button(window, text="Сохранить этот отчёт…", command=save).pack(pady=10)

    def run_diagnostics(self):
        self.refresh_happ()
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.check_button.configure(state="disabled", text="Проверяем…")
        self.store.event("diagnostic", "INFO", "Запущена диагностика DNS и HTTPS")
        self._refresh_events()
        threading.Thread(target=self._diagnostic_worker, daemon=True).start()

    def _diagnostic_worker(self):
        try:
            self._collect_diagnostics()
        except Exception:
            self.events_queue.put(("error", "Диагностика не завершена. Проверьте доступность локальной базы и повторите запуск."))

    def _collect_diagnostics(self):
        environment = environment_snapshot()
        checks = [
            ("dns", lambda: check_dns("claude.ai")),
            ("https", lambda: check_https(CLAUDE_URL)),
            ("dns", lambda: check_dns("www.anthropic.com")),
            ("https", lambda: check_https(ANTHROPIC_URL)),
        ]
        results = []
        for kind, fn in checks:
            r = fn()
            r["kind"] = kind
            results.append(r)
            self.events_queue.put(("result", r))
        score, summary = calculate_network_score(results)
        self.store.save_run(score, summary, results, environment)
        warnings = [r for r in results if r.get("kind") == "https" and r.get("status") != "response_received"]
        self.store.event("diagnostic", "OK" if score == 100 and not warnings else "WARN",
                         f"Диагностика завершена: {score}/100", summary)
        self.events_queue.put(("done", (score, summary)))

    def _drain_queue(self):
        try:
            while True:
                kind, payload = self.events_queue.get_nowait()
                if kind == "happ":
                    self.happ_detection_running = False
                    self.happ_button.configure(state="normal")
                    running = {True: "запущен", False: "не обнаружен", None: "проверка недоступна"}[payload["happ_running"]]
                    self.happ_label.configure(text=f"Happ: {running}. {payload['summary']}.\n{payload['limitation']}")
                elif kind == "result":
                    r = payload
                    status = ("ОТВЕТ" if r.get("status") == "response_received" else "ВНИМАНИЕ") if r.get("kind") == "https" and r["ok"] else ("OK" if r["ok"] else "ОШИБКА")
                    self.results_tree.insert("", "end", values=(
                        status, r["name"], r["detail"], r["duration_ms"]
                    ))
                elif kind == "error":
                    self.check_button.configure(state="normal", text="Запустить диагностику")
                    self.score_label.configure(text="—")
                    self.score_text.configure(text=payload)
                    messagebox.showerror("Ошибка диагностики", payload)
                elif kind == "done":
                    score, summary = payload
                    self.score_label.configure(text=f"{score}/100")
                    self.score_text.configure(text=summary + "\nДаже 100/100 не подтверждает доступ: проверьте HTTP-статусы в таблице.")
                    self.check_button.configure(state="normal", text="Запустить диагностику")
                    self._refresh_events()
                    self._refresh_history()
        except queue.Empty:
            pass
        self.after(150, self._drain_queue)

    def refresh_happ(self):
        if self.happ_detection_running:
            return
        self.happ_detection_running = True
        self.happ_button.configure(state="disabled")
        self.happ_label.configure(text="Проверяем Happ и настройки Windows…")
        def worker():
            try:
                result = detect_happ()
            except Exception:
                result = {"happ_running": None, "summary": "Не удалось определить режим",
                          "limitation": "Маршрут Claude Desktop не подтверждён."}
            self.events_queue.put(("happ", result))
        threading.Thread(target=worker, daemon=True).start()

    def show_environment(self):
        report = environment_snapshot()
        present = [name for name, exists in report["variables_present"].items() if exists]
        proxy_types = [name for name, exists in report["python_proxy_configured"].items() if exists]
        messagebox.showinfo("Среда / прокси",
                            "Переменные заданы: " + (", ".join(present) or "не обнаружены") +
                            "\nНастройки прокси Python: " + (", ".join(proxy_types) or "не обнаружены") +
                            "\n\n" + report["scope"] +
                            "\nНаличие или отсутствие этих настроек не подтверждает маршрут VPN.")

    def check_processes(self):
        found, note = get_running_processes()
        details = "\n".join(found) if found else "Процессы Claude/v2rayN/sing-box не обнаружены."
        self.store.event("processes", "INFO" if found else "WARN", note, details)
        messagebox.showinfo("Проверка процессов", note + "\n\n" + details)
        self._refresh_events()

    def _refresh_events(self):
        if not hasattr(self, "log_tree"):
            return
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)
        for timestamp, category, status, message, details in self.store.recent_events():
            self.log_tree.insert("", "end", values=(timestamp, category, status, message), tags=())
        self.log_tree.yview_moveto(0)

    def export_events(self):
        path = filedialog.asksaveasfilename(
            title="Экспорт журнала",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("Текст", "*.txt")],
            initialfile="obman-events.json",
        )
        if not path:
            return
        rows = self.store.recent_events(5000)
        data = [
            {"timestamp": r[0], "category": r[1], "status": r[2], "message": r[3], "details": r[4]}
            for r in rows
        ]
        try:
            if path.lower().endswith(".json"):
                Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            else:
                Path(path).write_text(
                    "\n".join(f"{r['timestamp']} [{r['category']}/{r['status']}] {r['message']} {r['details']}"
                              for r in data),
                    encoding="utf-8",
                )
            messagebox.showinfo("Экспорт", f"Экспортировано событий: {len(data)}")
        except OSError as exc:
            messagebox.showerror("Ошибка экспорта", str(exc))


if __name__ == "__main__":
    app = ObmanApp()
    app.mainloop()
