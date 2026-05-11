import time
import csv
import os
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP

# ================= CONFIG =================
INTERVAL = 5  # seconds

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_FILE = os.path.join(BASE_DIR, "ml_engine", "live_traffic.csv")

# ================= STATE =================
ip_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})

# ================= PACKET HANDLER =================
def process_packet(pkt):
    if IP not in pkt:
        return

    src_ip = pkt[IP].src

    # Ignore invalid / placeholder IPs
    if src_ip.startswith("0.") or src_ip == "127.0.0.1":
        return

    ip_stats[src_ip]["packets"] += 1
    ip_stats[src_ip]["bytes"] += len(pkt)
 
# ================= CSV WRITER =================
def write_csv():
    now = datetime.utcnow().isoformat()

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ip",
            "duration",
            "packets",
            "bytes",
            "rate",
            "last_seen"
        ])

        for ip, s in ip_stats.items():
            rate = round(s["packets"] / INTERVAL, 2)
            writer.writerow([
                ip,
                INTERVAL,
                s["packets"],
                s["bytes"],
                rate,
                now
            ])

# ================= MAIN LOOP =================
def main():
    print("[CAPTURE] SecureML traffic capture started")

    while True:
        ip_stats.clear()

        sniff(
            filter="ip",
            prn=process_packet,
            timeout=INTERVAL,
            store=False
        )

        write_csv()

        for ip, s in ip_stats.items():
            print(
                f"[CAPTURE] {ip} → "
                f"packets={s['packets']}, "
                f"bytes={s['bytes']}, "
                f"rate={s['packets']/INTERVAL:.2f}"
            )

        time.sleep(1)

# ================= ENTRY =================
if __name__ == "__main__":
    main()
