import subprocess
import threading
import time
import os
from datetime import datetime, timedelta

# ---------------- PATH FIX ----------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "blocked_ips.log")

BLOCK_DURATION = 300  # seconds (5 minutes)

os.makedirs(LOG_DIR, exist_ok=True)

# In-memory TTL registry
BLOCK_EXPIRY = {}


def is_ip_blocked(ip):
    result = subprocess.run(
        ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0


def unblock_ip(ip):
    try:
        subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        BLOCK_EXPIRY.pop(ip, None)
        log_event(f"UNBLOCKED ip={ip}")
        print(f"[SECUREML] 🔓 Unblocked IP: {ip}")
    except subprocess.CalledProcessError:
        pass


def schedule_unblock(ip, duration):
    time.sleep(duration)
    unblock_ip(ip)


def block_ip(ip, reason="High-confidence anomaly"):
    if is_ip_blocked(ip):
        return "already_blocked"

    try:
        subprocess.run(
            ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )

        expiry = datetime.utcnow() + timedelta(seconds=BLOCK_DURATION)
        BLOCK_EXPIRY[ip] = expiry

        log_event(
            f"BLOCKED ip={ip} duration={BLOCK_DURATION}s reason='{reason}'"
        )
        print(f"[SECUREML] 🔒 Blocked IP: {ip}")

        t = threading.Thread(
            target=schedule_unblock,
            args=(ip, BLOCK_DURATION),
            daemon=True
        )
        t.start()

        return "blocked"

    except subprocess.CalledProcessError as e:
        log_event(f"ERROR ip={ip} error={str(e)}")
        return "error"


def get_block_remaining(ip):
    """
    Returns remaining block time in seconds
    """
    if ip not in BLOCK_EXPIRY:
        return 0

    remaining = (BLOCK_EXPIRY[ip] - datetime.utcnow()).total_seconds()
    return max(0, int(remaining))


def log_event(message):
    timestamp = datetime.utcnow().isoformat()
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} {message}\n")
