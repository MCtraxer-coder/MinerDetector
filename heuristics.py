from config import (
    CPU_THRESHOLD, RAM_THRESHOLD, SYSTEM_PATHS,
    SYSTEM_PROCESS_NAMES, SUSPICIOUS_PATHS,
    MINING_PORTS, MINING_POOL_DOMAINS,
)
from network import get_all_connections

def _has_window(pid: int) -> bool:
    try:
        import win32gui
        import win32process

        def callback(hwnd, results):
            if win32gui.IsWindowVisible(hwnd):
                _, window_pid = win32process.GetWindowThreadProcessId(hwnd)
                if window_pid == pid:
                    results.append(hwnd)
            return True

        results = []
        win32gui.EnumWindows(callback, results)
        return len(results) > 0
    except Exception:
        return False

def _is_random_name(name: str) -> bool:
    name_lower = name.lower().replace(".exe", "").replace(".dll", "")

    if len(name_lower) < 4:
        return False

    parts = name_lower.split("_")
    if len(parts) > 1:
        for part in parts:
            if len(part) >= 5 and any(c in "aeiouy" for c in part):
                return False

    digit_count = sum(1 for c in name_lower if c.isdigit())
    if digit_count >= 4:
        return True

    vowels = sum(1 for c in name_lower if c in "aeiouyаеёиоуыэюя")
    if vowels == 0 and len(name_lower) > 5:
        return True

    return False

def check_process(proc: dict, connections: list = None) -> dict:

    flags = []
    score = 0

    name = proc.get("name", "").lower()
    path = (proc.get("path") or "").lower()
    cpu = proc.get("cpu", 0.0)
    ram = proc.get("ram", 0.0)

    if cpu > CPU_THRESHOLD:
        flags.append("high_cpu")
        score += 20

    if ram > RAM_THRESHOLD:
        flags.append("high_ram")
        score += 10

    in_system_path = any(sp in path for sp in SYSTEM_PATHS)
    if in_system_path:
        score = max(0, score - 30)

    in_suspicious_path = any(sp in path for sp in SUSPICIOUS_PATHS)
    if in_suspicious_path and not in_system_path:
        flags.append("suspicious_path")
        score += 25

    if name in [n.lower() for n in SYSTEM_PROCESS_NAMES]:
        if not in_system_path and path:
            flags.append("fake_system")
            score += 50

    if _is_random_name(name):
        flags.append("random_name")
        score += 25

    if cpu > CPU_THRESHOLD:
        pid = proc.get("pid")
        if pid and not _has_window(pid):
            flags.append("no_window")
            score += 30

    if connections:
        for conn in connections:
            port = conn.get("remote_port", 0)
            ip = conn.get("remote_ip", "").lower()

            if port in MINING_PORTS:
                flags.append("mining_port")
                score += 40
                break

            if any(domain in ip for domain in MINING_POOL_DOMAINS):
                flags.append("mining_pool")
                score += 50
                break

    score = min(score, 100)
    return {"flags": flags, "score": score}

def check_all_processes(processes: list) -> list:

    from monitor import get_process_connections

    try:
        all_system_conns = get_all_connections()
    except Exception:
        all_system_conns = []

    conns_by_pid = {}
    for c in all_system_conns:
        pid = c["pid"]
        if pid not in conns_by_pid:
            conns_by_pid[pid] = []
        conns_by_pid[pid].append(c)

    result = []
    for proc in processes:
        pid = proc.get("pid")

        process_conns = conns_by_pid.get(pid, [])

        if proc.get("cpu", 0) > CPU_THRESHOLD:
            detail_conns = get_process_connections(pid)
            process_conns = process_conns + detail_conns

        check = check_process(proc, process_conns)
        proc["flags"] = check["flags"]
        proc["score"] = check["score"]
        result.append(proc)

    return result

if __name__ == "__main__":
    from monitor import get_processes

    print("Собираю процессы...\n")
    procs = get_processes()

    print("Проверяю эвристиками...\n")
    procs = check_all_processes(procs)
    procs.sort(key=lambda p: p["score"], reverse=True)

    print(f"{'SCORE':<6} {'PID':<8} {'ИМЯ':<30} {'CPU%':<8} {'ФЛАГИ'}")
    print("-" * 90)

    for p in procs[:20]:
        name = p["name"][:28] if len(p["name"]) > 28 else p["name"]
        flags = ", ".join(p["flags"]) if p["flags"] else "—"
        print(f"{p['score']:<6} {p['pid']:<8} {name:<30} {p['cpu']:<8.1f} {flags}")