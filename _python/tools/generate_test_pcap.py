"""
Tạo file PCAP mô phỏng các kịch bản tấn công DDoS để kiểm thử.

Cách dùng:
    python tools/generate_test_pcap.py

Output: sample_pcap/ thư mục chứa các file .pcap
"""
import random
import sys
import os

# Make sure scapy is importable
try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, Ether,
        wrpcap, RandShort, RandIP,
    )
except ImportError:
    print("Lỗi: scapy chưa được cài đặt.")
    print("Chạy:  pip install scapy")
    sys.exit(1)

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_pcap")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def _ts(base: float, offset: float, jitter: float = 0.001) -> float:
    return base + offset + random.uniform(0, jitter)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Normal traffic
# ─────────────────────────────────────────────────────────────────────────────
def make_normal(out: str, n: int = 500):
    pkts = []
    ips = [f"192.168.1.{i}" for i in range(1, 20)]
    server = "10.0.0.1"
    t = 0.0
    for _ in range(n):
        src = random.choice(ips)
        proto = random.choices(["tcp", "udp", "icmp"], weights=[6, 2, 1])[0]
        t += random.uniform(0.002, 0.05)
        if proto == "tcp":
            flags = random.choice(["S", "SA", "A", "PA", "FA"])
            p = (IP(src=src, dst=server, ttl=64) /
                 TCP(sport=RandShort(), dport=random.choice([80, 443, 8080]),
                     flags=flags))
        elif proto == "udp":
            p = (IP(src=src, dst=server, ttl=64) /
                 UDP(sport=RandShort(), dport=53))
        else:
            p = IP(src=src, dst=server, ttl=64) / ICMP()
        p.time = t
        pkts.append(p)
    wrpcap(out, pkts)
    print(f"[OK] Normal traffic  → {out}  ({len(pkts)} packets)")


# ─────────────────────────────────────────────────────────────────────────────
# 2. SYN Flood
# ─────────────────────────────────────────────────────────────────────────────
def make_syn_flood(out: str, n_attack: int = 2000, n_normal: int = 200):
    pkts = []
    attacker = "10.10.10.99"
    victim   = "192.168.1.1"
    t = 0.0

    # Normal traffic before attack
    for _ in range(100):
        t += random.uniform(0.01, 0.05)
        p = (IP(src=f"192.168.1.{random.randint(2,50)}", dst=victim, ttl=64) /
             TCP(sport=RandShort(), dport=80, flags="S"))
        p.time = t
        pkts.append(p)

    # Attack burst (2000 SYN in ~4 seconds)
    attack_start = t + 0.5
    for i in range(n_attack):
        t = attack_start + i * 0.002 + random.uniform(0, 0.001)
        p = (IP(src=attacker, dst=victim, ttl=random.randint(32, 128)) /
             TCP(sport=random.randint(1024, 65535), dport=80, flags="S",
                 seq=random.randint(0, 2**32)))
        p.time = t
        pkts.append(p)

    # Some normal traffic during/after
    for _ in range(n_normal):
        t += random.uniform(0.005, 0.03)
        p = (IP(src=f"192.168.1.{random.randint(2,50)}", dst=victim, ttl=64) /
             TCP(sport=RandShort(), dport=80, flags="PA"))
        p.time = t
        pkts.append(p)

    pkts.sort(key=lambda x: x.time)
    wrpcap(out, pkts)
    print(f"[OK] SYN Flood       → {out}  ({len(pkts)} packets, {n_attack} attack)")


# ─────────────────────────────────────────────────────────────────────────────
# 3. UDP Flood
# ─────────────────────────────────────────────────────────────────────────────
def make_udp_flood(out: str, n: int = 3000):
    pkts = []
    victim = "192.168.1.1"
    sources = [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
               for _ in range(20)]
    t = 0.0
    for i in range(n):
        t += random.uniform(0.0005, 0.003)
        src = random.choice(sources)
        p = (IP(src=src, dst=victim, ttl=random.randint(32, 128)) /
             UDP(sport=random.randint(1024, 65535),
                 dport=random.randint(1, 65535)))
        p.time = t
        pkts.append(p)
    wrpcap(out, pkts)
    print(f"[OK] UDP Flood       → {out}  ({len(pkts)} packets)")


# ─────────────────────────────────────────────────────────────────────────────
# 4. ICMP Flood
# ─────────────────────────────────────────────────────────────────────────────
def make_icmp_flood(out: str, n: int = 1500):
    pkts = []
    victim = "192.168.1.1"
    t = 0.0
    for i in range(n):
        t += random.uniform(0.001, 0.01)
        src = f"172.16.{random.randint(0,5)}.{random.randint(1,254)}"
        p = (IP(src=src, dst=victim, ttl=64) / ICMP(type=8))   # Echo Request
        p.time = t
        pkts.append(p)
    wrpcap(out, pkts)
    print(f"[OK] ICMP Flood      → {out}  ({len(pkts)} packets)")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Mixed / DDoS scenario  (combines all attack types + normal)
# ─────────────────────────────────────────────────────────────────────────────
def make_mixed(out: str):
    pkts = []
    victim = "192.168.1.100"
    t = 0.0

    # --- Phase 1: Normal (0–5s) ---
    for _ in range(300):
        t += random.uniform(0.01, 0.05)
        src = f"192.168.1.{random.randint(2, 50)}"
        p = (IP(src=src, dst=victim, ttl=64) /
             TCP(sport=RandShort(), dport=80, flags="PA"))
        p.time = t
        pkts.append(p)

    # --- Phase 2: Port Scan (5–8s) ---
    scanner = "172.16.0.5"
    t = 5.0
    for port in range(1, 500):
        t += 0.006
        p = (IP(src=scanner, dst=victim, ttl=64) /
             TCP(sport=random.randint(1024, 65535), dport=port, flags="S"))
        p.time = t
        pkts.append(p)

    # --- Phase 3: SYN Flood (8–12s) ---
    attacker_syn = "10.0.0.55"
    t = 8.0
    for _ in range(1200):
        t += 0.003 + random.uniform(0, 0.001)
        p = (IP(src=attacker_syn, dst=victim, ttl=64) /
             TCP(sport=random.randint(1024, 65535), dport=80, flags="S"))
        p.time = t
        pkts.append(p)

    # --- Phase 4: UDP Flood (12–15s) ---
    udp_srcs = [f"203.0.113.{i}" for i in range(1, 30)]
    t = 12.0
    for _ in range(1500):
        t += 0.002
        src = random.choice(udp_srcs)
        p = (IP(src=src, dst=victim, ttl=128) /
             UDP(sport=random.randint(1024, 65535),
                 dport=random.randint(1, 65535)))
        p.time = t
        pkts.append(p)

    # --- Phase 5: ICMP Flood (15–18s) ---
    t = 15.0
    for _ in range(500):
        t += 0.006
        src = f"198.51.100.{random.randint(1, 100)}"
        p = IP(src=src, dst=victim, ttl=64) / ICMP(type=8)
        p.time = t
        pkts.append(p)

    # --- Phase 6: Back to normal (18–20s) ---
    for _ in range(200):
        t += random.uniform(0.01, 0.05)
        src = f"192.168.1.{random.randint(2, 50)}"
        p = (IP(src=src, dst=victim, ttl=64) /
             TCP(sport=RandShort(), dport=443, flags="A"))
        p.time = t
        pkts.append(p)

    pkts.sort(key=lambda x: x.time)
    wrpcap(out, pkts)
    print(f"[OK] Mixed DDoS      → {out}  ({len(pkts)} packets, ~20s timeline)")


# ─────────────────────────────────────────────────────────────────────────────
# 6. Single-source DoS
# ─────────────────────────────────────────────────────────────────────────────
def make_single_source(out: str, n: int = 1000):
    pkts = []
    attacker = "192.168.100.200"
    victim   = "10.0.0.1"
    t = 0.0
    for _ in range(n):
        t += 0.001 + random.uniform(0, 0.0005)
        proto = random.choice(["tcp", "udp"])
        if proto == "tcp":
            p = (IP(src=attacker, dst=victim, ttl=64) /
                 TCP(sport=random.randint(1024, 65535), dport=8080, flags="S"))
        else:
            p = (IP(src=attacker, dst=victim, ttl=64) /
                 UDP(sport=random.randint(1024, 65535), dport=9000))
        p.time = t
        pkts.append(p)
    # add a few normal
    for _ in range(50):
        t += random.uniform(0.01, 0.05)
        p = (IP(src=f"192.168.1.{random.randint(1,20)}", dst=victim, ttl=64) /
             TCP(sport=RandShort(), dport=80, flags="A"))
        p.time = t
        pkts.append(p)
    pkts.sort(key=lambda x: x.time)
    wrpcap(out, pkts)
    print(f"[OK] Single-source   → {out}  ({len(pkts)} packets)")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace") if hasattr(sys.stdout, "reconfigure") else None
    print("=" * 60)
    print(" Generate sample PCAP files for DDoS Analyzer")
    print("=" * 60)

    make_normal(       os.path.join(OUTPUT_DIR, "normal_traffic.pcap"))
    make_syn_flood(    os.path.join(OUTPUT_DIR, "syn_flood.pcap"))
    make_udp_flood(    os.path.join(OUTPUT_DIR, "udp_flood.pcap"))
    make_icmp_flood(   os.path.join(OUTPUT_DIR, "icmp_flood.pcap"))
    make_single_source(os.path.join(OUTPUT_DIR, "single_source_dos.pcap"))
    make_mixed(        os.path.join(OUTPUT_DIR, "mixed_ddos.pcap"))

    print()
    print(f"All files saved to: {OUTPUT_DIR}/")
    print("Open DDoS Analyzer and use File > Open to load them.")
