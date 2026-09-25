from pathlib import Path
PROJECT_DIR = Path(__file__).parent
DB_PATH = str(PROJECT_DIR / "miner_detector.db")
LOG_PATH = PROJECT_DIR / "derector.log"

MONITOR_INTERVAL = 5
STARTUP_CHECK_INTERVAL = 60
NETWORK_CHECK_INTERVAL = 10
CPU_THRESHOLD = 80.0
RAM_THRESHOLD = 500.0
MINER_LIFETIME_THRESHOLD = 300
SCORE_RED = 70
SCORE_ORANGE = 40
SCORE_YELLOW = 1

SYSTEM_PATHS = [
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",
    "c:\\program files",
    "c:\\program files (x86)",
]

SYSTEM_PROCESS_NAMES = [
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "winlogon.exe",
    "services.exe",
    "smss.exe",
    "wininit.exe",
    "explorer.exe",
    "dwm.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "sihost.exe",
    "ctfmon.exe",
]

SUSPICIOUS_PATHS = [
    "\\appdata\\local\\temp",
    "\\appdata\\local\\tmp",
    "\\windows\\temp",
    "\\users\\public",
]

MINING_PORTS = [
    3333, 4444, 5555, 7777, 8888, 9999,
    14444, 14433, 45700,
    3032, 3010,
]

MINING_POOL_DOMAINS = [
    "minexmr",
    "nanopool",
    "nicehash",
    "minergate",
    "supportxmr",
    "moneroocean",
    "2miners",
    "flexpool",
    "ethermine",
    "f2pool",
    "antpool",
    "viabtc",
    "poolin",
    "sparkpool",
]

PROTECTED_PROCESSES = [
    "system",
    "system idle process",
    "registry",
    "memory compression",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "smss.exe",
]
DB_RETENTION_DAYS = 30
LOG_LEVEL = "INFO"
