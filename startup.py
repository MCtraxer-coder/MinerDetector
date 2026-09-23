import winreg
import subprocess
from pathlib import Path
from config import SUSPICIOUS_PATHS, SYSTEM_PATHS
from heuristics import _is_random_name

def get_startup_registry() -> list:
    entries = []
    entries.extend(_read_registry_run(winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run",
        "registry_hkcu",))
    entries.extend(_read_registry_run(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run",
        "registry_hklm",))
    return entries
def _read_registry_run(hive, subkey: str, source_name: str) -> list:
    entries = []
    try:
        with winreg.OpenKey(hive, subkey) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    entries.append({
                        "source": source_name,
                        "name": name,
                        "path": value,
                        "enabled": True,
                    })
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        pass
    except PermissionError:
        pass
    return entries

def get_startup_folder() -> list:
    entries = []
    startup_dir = Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    if not startup_dir.exists():
        return []
    for item in startup_dir.iterdir():
        entries.append({
            "source": "startup_folder",
            "name": item.name,
            "path": str(item),
            "enabled": True,
        })
    return entries
def get_scheduled_tasks() -> list:
    entries = []
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "csv", "/v"],
            capture_output=True,
            text=True,
            encoding="cp866",
            timeout=30,
        )
        if result.returncode != 0:
            return []
        lines = result.stdout.splitlines()
        if len(lines) < 2:
            return []
        headers = [h.strip('"') for h in lines[0].split('","')]
        try:
            name_idx = headers.index("TaskName")
            status_idx = headers.index("Status")
            command_idx = headers.index("Task To Run")
            schedule_idx = headers.index("Schedule Type")
        except ValueError:
            return []
        for line in lines[1:]:
            parts =  [p.strip('"') for p in line.split('","')]
            if len(parts) <= max(name_idx, status_idx, command_idx, schedule_idx):
                continue
            task_name = parts[name_idx]
            status = parts[status_idx]
            command = parts[command_idx]
            schedule = parts[schedule_idx]
            if schedule.lower() in ("on demand only", "по требованию"):
                continue
            if status.lower() not in ("ready", "running", "готово", "выполняется"):
                continue
            entries.append({
                "source": "scheduler",
                "name": task_name,
                "path": command,
                "enabled": True,
            })
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return entries

def check_startup_entry(entry: dict) -> dict:
    flags = []
    score = 0

    name = entry.get("name", "").lower()
    path = (entry.get("path") or "").lower()

    in_suspicious = any(sp in path for sp in SUSPICIOUS_PATHS)
    in_system = any(sp in path for sp in SYSTEM_PATHS)

    if in_suspicious and not in_system:
        flags.append("suspicious_path")
        score += 30

    if _is_random_name(name):
        flags.append("random_name")
        score += 25

    if path.endswith((".vbs", ".js", ".wsf", ".hta")):
        flags.append("script_execution")
        score += 35

    if "powershell" in path and ("-enc" in path or "-e " in path or "encodedcommand" in path):
        flags.append("encoded_powershell")
        score += 60

    if "\\temp\\" in path or "\\tmp\\" in path:
        flags.append("temp_execution")
        score += 40

    if not path:
        flags.append("empty_path")
        score += 20

    if name == "desktop.ini":
        return {"flags": [], "score": 0}

    score = min(score, 100)
    return {"flags": flags, "score": score}

def get_all_startup() -> list:

    all_entries = []
    all_entries.extend(get_startup_registry())
    all_entries.extend(get_startup_folder())
    all_entries.extend(get_scheduled_tasks())
    for entry in all_entries:
        check = check_startup_entry(entry)
        entry["flags"] = check["flags"]
        entry["score"] = check["score"]
    all_entries.sort(key=lambda e: e["score"], reverse=True)

    return all_entries

if __name__ == "__main__":
    print("Собираю автозагрузку...\n")
    entries = get_all_startup()

    print(f"Всего записей: {len(entries)}\n")
    print(f"{'SCORE':<6} {'ИСТОЧНИК':<18} {'ИМЯ':<35} {'ПУТЬ'}")
    print("-" * 130)

    for e in entries[:30]:
        source = e["source"][:16]
        name = e["name"][:33] if len(e["name"]) > 33 else e["name"]
        path = e["path"] or "<пусто>"
        if len(path) > 60:
            path = "..." + path[-57:]
        print(f"{e['score']:<6} {source:<18} {name:<35} {path}")