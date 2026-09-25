
import customtkinter as ctk
from tkinter import ttk, messagebox
import threading
import time

from config import MONITOR_INTERVAL
from monitor import get_processes, kill_process
from heuristics import check_all_processes
from startup import get_all_startup
from network import get_all_connections
from db import (
    init_db,
    save_processes_batch,
    save_event,
    get_top_suspicious,
)

BG_COLOR = "#000000"
FG_COLOR = "#ffffff"
FRAME_COLOR = "#0a0a0a"
BUTTON_GRAY = "#1a1a1a"
BUTTON_HOVER = "#2a2a2a"
TABLE_BG = "#000000"
TABLE_FG = "#ffffff"
TABLE_SELECT = "#1e3a5f"
TABLE_HEADING_BG = "#111111"


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class MinerDetectorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Miner Detector")
        self.geometry("1400x800")
        self.minsize(1000, 600)
        self.configure(fg_color=BG_COLOR)

        self.monitoring = False
        self.monitor_thread = None

        self.pid_by_item_id = {}
        self.kill_callback_by_item_id = {}   

        self._setup_tree_style()

        self.top_frame = ctk.CTkFrame(self, fg_color=FRAME_COLOR)
        self.top_frame.pack(fill="x", padx=10, pady=10)

        self.start_button = ctk.CTkButton(
            self.top_frame,
            text="▶ Запустить мониторинг",
            fg_color="green",
            hover_color="darkgreen",
            text_color=FG_COLOR,
            command=self.on_start_monitoring,
        )
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ctk.CTkButton(
            self.top_frame,
            text="■ Остановить",
            fg_color=BUTTON_GRAY,
            hover_color=BUTTON_HOVER,
            text_color=FG_COLOR,
            command=self.on_stop_monitoring,
            state="disabled",
        )
        self.stop_button.pack(side="left", padx=5)

        self.refresh_button = ctk.CTkButton(
            self.top_frame,
            text="🔄 Обновить всё",
            fg_color=BUTTON_GRAY,
            hover_color=BUTTON_HOVER,
            text_color=FG_COLOR,
            command=self.refresh_all,
        )
        self.refresh_button.pack(side="left", padx=5)

        self.kill_button = ctk.CTkButton(
            self.top_frame,
            text="☠ Убить процесс",
            fg_color="darkred",
            hover_color="red",
            text_color=FG_COLOR,
            command=self.on_kill_process,
        )
        self.kill_button.pack(side="left", padx=5)

        self.tabs = ctk.CTkTabview(
            self,
            fg_color=FRAME_COLOR,
            segmented_button_fg_color=BUTTON_GRAY,
            segmented_button_selected_color="#1e3a5f",
            segmented_button_selected_hover_color="#2e4a6f",
            text_color=FG_COLOR,
        )
        self.tabs.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.tabs.add("Процессы")
        self.tabs.add("Автозагрузка")
        self.tabs.add("Сеть")

        self._build_processes_tab()

        self._build_startup_tab()

        self._build_network_tab()

        self.status_label = ctk.CTkLabel(
            self,
            text="Готов. Нажми «Запустить мониторинг».",
            anchor="w",
            text_color=FG_COLOR,
            fg_color=BG_COLOR,
        )
        self.status_label.pack(fill="x", padx=10, pady=(0, 10))

        init_db()

    def _setup_tree_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Custom.Treeview",
            background=TABLE_BG,
            foreground=TABLE_FG,
            fieldbackground=TABLE_BG,
            borderwidth=0,
            font=("Consolas", 10),
            rowheight=24,
        )
        style.configure(
            "Custom.Treeview.Heading",
            background=TABLE_HEADING_BG,
            foreground=TABLE_FG,
            relief="flat",
            font=("Consolas", 10, "bold"),
        )
        style.map(
            "Custom.Treeview.Heading",
            background=[("active", "#1a1a1a")],
        )
        style.map(
            "Custom.Treeview",
            background=[("selected", TABLE_SELECT)],
            foreground=[("selected", TABLE_FG)],
        )
        style.configure(
            "Custom.Vertical.TScrollbar",
            background="#1a1a1a",
            troughcolor=BG_COLOR,
            bordercolor=BG_COLOR,
            arrowcolor=FG_COLOR,
        )

    def _build_processes_tab(self):
        tab = self.tabs.tab("Процессы")

        # Фильтр
        filter_frame = ctk.CTkFrame(tab, fg_color=FRAME_COLOR)
        filter_frame.pack(fill="x", padx=5, pady=5)

        self.only_suspicious = ctk.BooleanVar(value=True)
        self.filter_checkbox = ctk.CTkCheckBox(
            filter_frame,
            text="Только подозрительные (score > 0)",
            variable=self.only_suspicious,
            text_color=FG_COLOR,
            fg_color="#333333",
            hover_color="#555555",
            checkmark_color=FG_COLOR,
            command=self.refresh_processes,
        )
        self.filter_checkbox.pack(side="left", padx=5)

        # Таблица
        table_frame = ctk.CTkFrame(tab, fg_color=FRAME_COLOR)
        table_frame.pack(fill="both", expand=True, padx=5, pady=5)

        columns = [
            ("score", "Score", 60, "center"),
            ("pid", "PID", 70, "center"),
            ("name", "Имя", 200, "w"),
            ("cpu", "CPU%", 70, "e"),
            ("ram", "RAM МБ", 80, "e"),
            ("path", "Путь", 400, "w"),
            ("flags", "Флаги", 250, "w"),
        ]

        self.tree_processes = ttk.Treeview(
            table_frame,
            columns=[c[0] for c in columns],
            show="headings",
            selectmode="browse",
            style="Custom.Treeview",
        )

        for col_id, col_title, col_width, col_anchor in columns:
            self.tree_processes.heading(col_id, text=col_title)
            self.tree_processes.column(col_id, width=col_width, anchor=col_anchor)

        self.tree_processes.tag_configure("red", foreground="#ff5555", background=TABLE_BG)
        self.tree_processes.tag_configure("orange", foreground="#ffaa55", background=TABLE_BG)
        self.tree_processes.tag_configure("yellow", foreground="#ffff55", background=TABLE_BG)
        self.tree_processes.tag_configure("green", foreground="#55ff55", background=TABLE_BG)

        scrollbar = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.tree_processes.yview,
            style="Custom.Vertical.TScrollbar",
        )
        self.tree_processes.configure(yscrollcommand=scrollbar.set)

        self.tree_processes.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.tree_processes.bind("<<TreeviewSelect>>", self._on_process_select)

    def _on_process_select(self, event):
        selected = self.tree_processes.selection()
        if selected:
            item_id = selected[0]
            pid = self.pid_by_item_id.get(item_id)
            if pid:
                self.status_label.configure(text=f"Выбран PID: {pid}")

    def refresh_processes(self):
        for row in self.tree_processes.get_children():
            self.tree_processes.delete(row)
        self.pid_by_item_id.clear()

        rows = get_top_suspicious(200)

        if self.only_suspicious.get():
            rows = [r for r in rows if r["score"] > 0]

        seen_pids = set()
        unique_rows = []
        for r in rows:
            if r["pid"] not in seen_pids:
                seen_pids.add(r["pid"])
                unique_rows.append(r)

        for r in unique_rows:
            score = r["score"]

            if score >= 70:
                tag = "red"
            elif score >= 40:
                tag = "orange"
            elif score >= 1:
                tag = "yellow"
            else:
                tag = "green"

            path = r["path"] or "<недоступен>"
            if len(path) > 55:
                path = "..." + path[-52:]

            flags = r["flags"] or "—"

            item_id = self.tree_processes.insert("", "end", values=(
                score, r["pid"], r["name"],
                f"{r['cpu']:.1f}", f"{r['ram']:.1f}",
                path, flags,
            ), tags=(tag,))

            self.pid_by_item_id[item_id] = r["pid"]

    def _build_startup_tab(self):
        tab = self.tabs.tab("Автозагрузка")

        btn_frame = ctk.CTkFrame(tab, fg_color=FRAME_COLOR)
        btn_frame.pack(fill="x", padx=5, pady=5)

        ctk.CTkButton(
            btn_frame,
            text="🔄 Сканировать автозагрузку",
            fg_color=BUTTON_GRAY,
            hover_color=BUTTON_HOVER,
            text_color=FG_COLOR,
            command=self.refresh_startup,
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="🚫 Отключить запись",
            fg_color="darkred",
            hover_color="red",
            text_color=FG_COLOR,
            command=self.on_disable_startup,
        ).pack(side="left", padx=5)

        # Таблица
        table_frame = ctk.CTkFrame(tab, fg_color=FRAME_COLOR)
        table_frame.pack(fill="both", expand=True, padx=5, pady=5)

        columns = [
            ("score", "Score", 60, "center"),
            ("source", "Источник", 140, "w"),
            ("name", "Имя", 250, "w"),
            ("path", "Путь", 450, "w"),
            ("flags", "Флаги", 200, "w"),
        ]

        self.tree_startup = ttk.Treeview(
            table_frame,
            columns=[c[0] for c in columns],
            show="headings",
            selectmode="browse",
            style="Custom.Treeview",
        )

        for col_id, col_title, col_width, col_anchor in columns:
            self.tree_startup.heading(col_id, text=col_title)
            self.tree_startup.column(col_id, width=col_width, anchor=col_anchor)

        self.tree_startup.tag_configure("red", foreground="#ff5555", background=TABLE_BG)
        self.tree_startup.tag_configure("orange", foreground="#ffaa55", background=TABLE_BG)
        self.tree_startup.tag_configure("yellow", foreground="#ffff55", background=TABLE_BG)
        self.tree_startup.tag_configure("green", foreground="#55ff55", background=TABLE_BG)

        scrollbar = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.tree_startup.yview,
            style="Custom.Vertical.TScrollbar",
        )
        self.tree_startup.configure(yscrollcommand=scrollbar.set)

        self.tree_startup.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.startup_entries = {}

    def refresh_startup(self):
        self.status_label.configure(text="Сканирую автозагрузку...")

        threading.Thread(target=self._run_startup_scan, daemon=True).start()

    def _run_startup_scan(self):
        try:
            entries = get_all_startup()
        except Exception as e:
            self.after(0, lambda err=str(e): self.status_label.configure(text=f"Ошибка: {err}"))
            return

        self.after(0, lambda: self._fill_startup_table(entries))

    def _fill_startup_table(self, entries):
        for row in self.tree_startup.get_children():
            self.tree_startup.delete(row)

        self.startup_entries.clear()

        for e in entries:
            score = e.get("score", 0)

            if score >= 70:
                tag = "red"
            elif score >= 40:
                tag = "orange"
            elif score >= 1:
                tag = "yellow"
            else:
                tag = "green"

            path = e.get("path") or "<пусто>"
            if len(path) > 60:
                path = "..." + path[-57:]

            flags = ", ".join(e.get("flags", [])) or "—"

            item_id = self.tree_startup.insert("", "end", values=(
                score,
                e.get("source", "?"),
                e.get("name", "?"),
                path,
                flags,
            ), tags=(tag,))

            self.startup_entries[item_id] = e

        self.status_label.configure(text=f"Автозагрузка: {len(entries)} записей")

    def on_disable_startup(self):
        selected = self.tree_startup.selection()
        if not selected:
            messagebox.showwarning("Ничего не выбрано", "Выбери запись в таблице.")
            return

        item_id = selected[0]
        entry = self.startup_entries.get(item_id)
        if not entry:
            return

        source = entry.get("source", "")
        name = entry.get("name", "")

        if source == "registry_hkcu":
            confirmed = messagebox.askyesno(
                "Подтверждение",
                f"Отключить запись?\n\nИсточник: HKCU\\Run\nИмя: {name}",
            )
            if not confirmed:
                return

            try:
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, name)

                save_event("startup_disabled", None, name, entry.get("path"), f"Отключено из {source}")
                self.status_label.configure(text=f"Отключено: {name}")
                self.refresh_startup()

            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
        else:
            messagebox.showinfo(
                "Пока не поддерживается",
                f"Отключение из '{source}' пока не реализовано.\n"
                f"Отключи вручную через Диспетчер задач → Автозагрузка.",
            )

    def _build_network_tab(self):
        tab = self.tabs.tab("Сеть")

        btn_frame = ctk.CTkFrame(tab, fg_color=FRAME_COLOR)
        btn_frame.pack(fill="x", padx=5, pady=5)

        ctk.CTkButton(
            btn_frame,
            text="🔄 Сканировать сеть",
            fg_color=BUTTON_GRAY,
            hover_color=BUTTON_HOVER,
            text_color=FG_COLOR,
            command=self.refresh_network,
        ).pack(side="left", padx=5)

        self.only_pools = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            btn_frame,
            text="Только майнинг-пулы",
            variable=self.only_pools,
            text_color=FG_COLOR,
            fg_color="#333333",
            hover_color="#555555",
            checkmark_color=FG_COLOR,
            command=self.refresh_network,
        ).pack(side="left", padx=15)

        table_frame = ctk.CTkFrame(tab, fg_color=FRAME_COLOR)
        table_frame.pack(fill="both", expand=True, padx=5, pady=5)

        columns = [
            ("pid", "PID", 70, "center"),
            ("process", "Процесс", 200, "w"),
            ("remote", "Удалённый адрес", 250, "w"),
            ("status", "Статус", 120, "center"),
            ("flags", "Флаги", 200, "w"),
        ]

        self.tree_network = ttk.Treeview(
            table_frame,
            columns=[c[0] for c in columns],
            show="headings",
            selectmode="browse",
            style="Custom.Treeview",
        )

        for col_id, col_title, col_width, col_anchor in columns:
            self.tree_network.heading(col_id, text=col_title)
            self.tree_network.column(col_id, width=col_width, anchor=col_anchor)

        self.tree_network.tag_configure("red", foreground="#ff5555", background=TABLE_BG)
        self.tree_network.tag_configure("green", foreground="#55ff55", background=TABLE_BG)

        scrollbar = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.tree_network.yview,
            style="Custom.Vertical.TScrollbar",
        )
        self.tree_network.configure(yscrollcommand=scrollbar.set)

        self.tree_network.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def refresh_network(self):
        self.status_label.configure(text="Сканирую сеть...")
        threading.Thread(target=self._run_network_scan, daemon=True).start()

    def _run_network_scan(self):
        try:
            conns = get_all_connections()
        except Exception as e:
            self.after(0, lambda err=str(e): self.status_label.configure(text=f"Ошибка: {err}"))
            return

        self.after(0, lambda: self._fill_network_table(conns))

    def _fill_network_table(self, conns):
        for row in self.tree_network.get_children():
            self.tree_network.delete(row)

        if self.only_pools.get():
            conns = [c for c in conns if c["is_mining_pool"]]

        conns.sort(key=lambda c: (not c["is_mining_pool"], c["pid"]))

        for c in conns[:500]:
            tag = "red" if c["is_mining_pool"] else "green"

            remote = f"{c['remote_ip']}:{c['remote_port']}"
            flags = ", ".join(c["flags"]) if c["flags"] else "—"

            self.tree_network.insert("", "end", values=(
                c["pid"],
                c["process_name"],
                remote,
                c["status"],
                flags,
            ), tags=(tag,))

        self.status_label.configure(text=f"Соединений: {len(conns)}")

    def on_start_monitoring(self):
        if self.monitoring:
            return

        self.monitoring = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status_label.configure(text="Мониторинг запущен...")

        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def on_stop_monitoring(self):
        self.monitoring = False
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.status_label.configure(text="Мониторинг остановлен.")

    def _monitor_loop(self):
        while self.monitoring:
            try:
                procs = get_processes()
                procs = check_all_processes(procs)
                save_processes_batch(procs)

                for p in procs:
                    if p.get("score", 0) >= 70:
                        save_event(
                            "high_score",
                            p.get("pid"),
                            p.get("name"),
                            p.get("path"),
                            f"Score {p['score']}, флаги: {','.join(p.get('flags', []))}",
                        )

                self.after(0, self.refresh_processes)

            except Exception as e:
                self.after(0, lambda err=str(e): self.status_label.configure(text=f"Ошибка: {err}"))

            time.sleep(MONITOR_INTERVAL)

    def refresh_all(self):
        self.refresh_processes()
        self.refresh_startup()
        self.refresh_network()

    def on_kill_process(self):
        selected = self.tree_processes.selection()
        if not selected:
            messagebox.showwarning("Ничего не выбрано", "Выбери процесс в таблице «Процессы».")
            return

        item_id = selected[0]
        pid = self.pid_by_item_id.get(item_id)
        if not pid:
            return

        values = self.tree_processes.item(item_id, "values")
        name = values[2] if len(values) > 2 else f"PID {pid}"

        confirmed = messagebox.askyesno(
            "Подтверждение",
            f"Убить процесс?\n\nPID: {pid}\nИмя: {name}",
        )
        if not confirmed:
            return

        result = kill_process(pid)

        if result["success"]:
            save_event("process_killed", pid, name, None, "Убит пользователем")
            self.status_label.configure(text=f"Убит: {name} (PID {pid})")
            self.refresh_processes()
        else:
            messagebox.showerror("Ошибка", result["error"])

    def on_closing(self):
        self.monitoring = False
        self.destroy()


if __name__ == "__main__":
    app = MinerDetectorApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
