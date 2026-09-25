import sqlite3
from config import DB_PATH

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn
def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS processes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pid INTEGER,
            name TEXT,
            path TEXT,
            cpu REAL,
            ram REAL,
            flags TEXT,
            score INTEGER,
            snapshot_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            pid INTEGER,
            name TEXT,
            path TEXT,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS startup (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            name TEXT,
            path TEXT,
            enabled INTEGER,
            flags TEXT,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pid INTEGER,
            process_name TEXT,
            remote_ip TEXT,
            remote_port INTEGER,
            status TEXT,
            is_mining_pool INTEGER DEFAULT 0,
            snapshot_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_proc_score ON processes(score DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_proc_name ON processes(name)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_proc_created ON events(created_at DESC)")
    conn.commit()
    conn.close()

def save_process_snapshot(proc: dict):
    conn = get_connection()
    cursor = conn.cursor()
    flags_str = ",".join(proc.get("flags", []))
    cursor.execute("""
        INSERT INTO processes(pid, name, path, cpu, ram, flags, score)
        VALUES (?,?,?,?,?,?,?)""", (
        proc.get("pid"),
        proc.get("name"),
        proc.get("path"),
        proc.get("cpu", 0.0),
        proc.get("ram", 0.0),
        flags_str,
        proc.get("score", 0),
    ))
    conn.commit()
    conn.close()

def save_processes_batch(processes: list):
    conn = get_connection()
    cursor = conn.cursor()
    data = [
        (
            p.get("pid"),
            p.get("name"),
            p.get("path"),
            p.get("cpu", 0.0),
            p.get("ram", 0.0),
            ",".join(p.get("flags", [])),
            p.get("score", 0),
        )
        for p in processes
    ]
    cursor.executemany("""
        INSERT INTO processes (pid, name, path, cpu, ram, flags, score)
        VALUES (?,?,?,?,?,?,?)""", data)
    conn.commit()
    conn.close()

def save_event(event_type: str, pid: int = None, name: str = None,
               path: str = None, details: str = None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO events (event_type, pid, name, path, details)
        VAlUES (?,?,?,?,?)""", (event_type, pid, name, path, details))
    conn.commit()
    conn.close()
def save_startup_entry(source: str, name: str, path: str,
                       enabled: bool = True, flags: list = None):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO startup (source, name, path, enabled, flags)
        VALUES (?, ?, ?, ?, ?)
    """, (
        source,
        name,
        path,
        1 if enabled else 0,
        ",".join(flags or []),
    ))

    conn.commit()
    conn.close()

def save_connection(pid: int, process_name: str, remote_ip: str,
                    remote_port: int, status: str, is_mining_pool: bool = False):
    """Записывает сетевое соединение."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO connections (pid, process_name, remote_ip, remote_port, status, is_mining_pool)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        pid, process_name, remote_ip, remote_port, status,
        1 if is_mining_pool else 0,
    ))

    conn.commit()
    conn.close()

def get_top_suspicious(limit: int = 50) -> list:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT pid, name, path, cpu, ram, flags, score, snapshot_at
        FROM processes
        WHERE score > 0
        ORDER BY score DESC, snapshot_at DESC
        LIMIT ? 
    """, (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def get_events(limit: int = 100) -> list:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT event_type, pid, name, path, details, created_at
        FROM events
        ORDER BY created_at DESC
        LIMIT ? 
    """, (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def get_process_history(pid: int, limit: int = 100) -> list:
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT cpu, ram, score, snapshot_at
        FROM processes
        WHERE pid = ?
        ORDER BY snapshot_at DESC
        LIMIT ?
    """, (pid, limit))

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def cleanup_old(days: int = 30):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        DELETE FROM processes
        WHERE snapshot_at < datetime('now', ?)
    """, (f"-{days} days",))
    cursor.execute("""
        DELETE FROM connections
        WHERE snapshot_at < datetime('now', ?)
    """, (f"-{days} days",))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    print("Инициализирую БД...")
    init_db()
    print(f"БД создана: {DB_PATH}\n")

    # Тест: запишем тестовый процесс
    test_proc = {
        "pid": 99999,
        "name": "test_miner.exe",
        "path": "C:/Temp/test_miner.exe",
        "cpu": 95.0,
        "ram": 500.0,
        "flags": ["high_cpu", "no_window"],
        "score": 85,
    }
    save_process_snapshot(test_proc)
    print("Тестовый процесс записан.\n")

    # Тест: событие
    save_event("miner_found", 99999, "test_miner.exe",
               "C:/Temp/test_miner.exe", "Обнаружен майнер с score 85")
    print("Тестовое событие записано.\n")

    # Читаем обратно
    print("Топ подозрительных:")
    for row in get_top_suspicious(5):
        print(f"  [{row['score']}] {row['name']} — {row['flags']}")

    print("\nПоследние события:")
    for row in get_events(5):
        print(f"  [{row['event_type']}] {row['name']}: {row['details']}")
