import threading
import psutil
import socket

from config import MINING_PORTS, MINING_POOL_DOMAINS

_dns_cache = {}
_dns_lock = threading.Lock()

def get_all_connections() -> list:

    connections = []

    try:
        for conn in psutil.net_connections(kind='inet'):
            if not conn.raddr:
                continue
            process_name = "<unknown>"
            if conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            remote_ip = conn.raddr.ip if conn.raddr else ""
            remote_port = conn.raddr.port if conn.raddr else 0
            check = check_mining_pool(remote_ip, remote_port)

            connections.append({
                "pid": conn.pid or 0,
                "process_name": process_name,
                "local_ip": conn.laddr.ip if conn.laddr else "",
                "local_port": conn.laddr.port if conn.laddr else 0,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "status": conn.status,
                "is_mining_pool": check["is_pool"],
                "flags": check["flags"],
            })

    except psutil.AccessDenied:
        print("[WARN] Нет прав администратора — список соединений может быть неполным.")
    except OSError as e:
        print(f"[WARN] Ошибка сбора соединений: {e}")

    return connections

def check_mining_pool(ip: str, port: int) -> dict:
    flags = []
    is_pool = False
    if port in MINING_PORTS:
        flags.append("mining_port")
        is_pool = True
    if not is_pool and ip:
        is_local = (
            ip.startswith("127.")
            or ip.startswith("192.168.")
            or ip.startswith("10.")
            or ip.startswith("172.")
        )

        if not is_local:
            if ip in _dns_cache:
                cached = _dns_cache[ip]
                if cached["is_pool"]:
                    flags.extend("mining_pool")
                    is_pool = True
            else:
                try:
                    hostname = socket.gethostbyaddr(ip)[0].lower()
                    found = False
                    for domain in MINING_POOL_DOMAINS:
                        if domain in hostname:
                            flags.append("mining_pool")
                            is_pool = True
                            found = True
                            break
                    _dns_cache[ip] = {"is_pool": found, "flags": flags.copy()}
                except (socket.herror, socket.gaierror, OSError):
                    _dns_cache[ip] = {"is_pool": False, "flags": []}

    return {
        "is_pool": is_pool,
        "flags": flags,
    }

def get_suspicious_connections() -> list:
    all_conns = get_all_connections()
    return [c for c in all_conns if c["is_mining_pool"]]

def group_by_process(connections: list) -> dict:

    grouped = {}

    for conn in connections:
        pid = conn["pid"]
        if pid not in grouped:
            grouped[pid] = {
                "process_name": conn["process_name"],
                "connections": [],
            }
        grouped[pid]["connections"].append(conn)

    return grouped

if __name__ == "__main__":
    print("Собираю сетевые соединения...\n")

    conns = get_all_connections()

    print(f"Всего соединений: {len(conns)}\n")

    print(f"{'PID':<8} {'ПРОЦЕСС':<25} {'REMOTE':<25} {'СТАТУС':<12} {'ФЛАГИ'}")
    print("-" * 100)

    conns.sort(key=lambda c: (not c["is_mining_pool"], c["pid"]))

    for c in conns[:30]:
        remote = f"{c['remote_ip']}:{c['remote_port']}"
        name = c["process_name"][:23] if len(c["process_name"]) > 23 else c["process_name"]
        flags = ", ".join(c["flags"]) if c["flags"] else "—"
        print(f"{c['pid']:<8} {name:<25} {remote:<25} {c['status']:<12} {flags}")

    suspicious = get_suspicious_connections()
    print(f"\nПодозрительных (майнинг-пулы): {len(suspicious)}")

    if suspicious:
        print("\n--- ПОДОЗРИТЕЛЬНЫЕ ---")
        for c in suspicious:
            print(f"  {c['process_name']} (PID {c['pid']}) → "
                  f"{c['remote_ip']}:{c['remote_port']} [{','.join(c['flags'])}]")
