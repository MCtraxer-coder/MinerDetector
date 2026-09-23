import psutil
import time
from config import PROTECTED_PROCESSES
def get_processes() -> list:
    processes = []
    for proc in psutil.process_iter(['pid']):
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    time.sleep(0.1)
    for proc in psutil.process_iter([
        'pid', 'name', 'exe', 'cpu_percent',
        'memory_info', 'cmdline', 'create_time', 'status'
    ]):
        try:
            info = proc.info
            ram_mb = 0.0
            if info.get('memory_info'):
                ram_mb = round(info['memory_info'].rss / 1024 / 1024, 1)
            processes.append({
                "pid": info.get('pid'),
                "name": info.get('name') or "unknown",
                "path": info.get('exe') or "",
                "cpu": info.get('cpu_percent') or 0.0,
                "ram": ram_mb,
                "cmdline": info.get('cmdline') or [],
                "create_time": info.get('create_time') or 0.0,
                "status": info.get('status') or "unknown",
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return processes
def get_process_info(pid: int) -> dict:
    try:
        proc = psutil.Process(pid)
        info = proc.as_dict(attrs=[
            'pid', 'name', 'exe', 'cpu_percent',
            'memory_info', 'cmdline', 'create_time', 'status',
            'ppid',
        ])
        ram_mb = 0.0
        if info.get('memory_info'):
            ram_mb = round(info['memory_info'].rss / 1024 / 1024, 1)
        return {
            "pid": info['pid'],
            "name": info.get('name') or "unknown",
            "path": info.get('exe') or "",
            "cpu": info.get('cpu_percent') or 0.0,
            "ram": ram_mb,
            "cmdline": info.get('cmdline') or [],
            "create_time": info.get('create_time') or 0.0,
            "status": info.get('status') or "unknown",
            "ppid": info.get('ppid'),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None
def kill_process(pid: int) -> dict:
    try:
        proc = psutil.Process(pid)
        name = proc.name().lower()
        if name in [p.lower() for p in PROTECTED_PROCESSES]:
            return {
                "success": False,
                "error": f"Процесс '{name}' защищён (системный). Убийство запрещено.",
            }
        proc.terminate()
        try:
            proc.wait(timeout=3)
            return {"success": True, "error": None}
        except psutil.TimeoutExpired:
            proc.kill()
            return {"success": True, "error": None}
    except psutil.NoSuchProcess:
        return {"success": False, "error": "Процесс уже не существует"}
    except psutil.AccessDenied:
        return {"success": False, "error": "Нет прав для убийства процесса (нужен админ)"}
    except Exception as e:
        return {"success": False, "error": str(e)}
def get_process_connections(pid: int) -> list:
    connections = []

    try:
        proc = psutil.Process(pid)
        for conn in proc.net_connections(kind='inet'):
            if conn.raddr:
                connections.append({
                    "remote_ip": conn.raddr.ip,
                    "remote_port": conn.raddr.port,
                    "local_port": conn.laddr.port if conn.laddr else 0,
                    "status": conn.status,
                })
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    return connections

if __name__ == "__main__":
    print("Собираю список процессов...\n")
    procs = get_processes()
    procs.sort(key=lambda p: p["cpu"], reverse=True)

    print(f"Всего процессов: {len(procs)}\n")
    print(f"{'PID':<8} {'ИМЯ':<25} {'CPU%':<7} {'RAM МБ':<9} {'ПУТЬ'}")
    print("-" * 120)

    for p in procs[:20]:
        name = p["name"][:23] if len(p["name"]) > 23 else p["name"]
        path = p["path"] if p["path"] else "<недоступен>"
        if len(path) > 60:
            path = "..." + path[-57:]
        print(f"{p['pid']:<8} {name:<25} {p['cpu']:<7.1f} {p['ram']:<9.1f} {path}")


