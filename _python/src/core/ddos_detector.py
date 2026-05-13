import logging
from collections import Counter, defaultdict
from typing import List, Dict, Tuple

from .models import PacketInfo, Alert, AlertSeverity, AttackType, NetworkStats

logger = logging.getLogger(__name__)

# ── Thresholds ──────────────────────────────────────────────────────────────
SYN_PER_SOURCE_THRESH = 50       # SYN/s từ 1 IP → SYN Flood
SYN_TOTAL_THRESH = 200           # Tổng SYN/s từ nhiều IP → Distributed SYN Flood
UDP_TOTAL_THRESH = 500           # UDP packet/s
ICMP_TOTAL_THRESH = 50           # ICMP packet/s
HTTP_PER_SOURCE_THRESH = 100     # HTTP req/s từ 1 IP
VOLUMETRIC_THRESH_MB = 5.0       # MB/s băng thông
SINGLE_SOURCE_RATIO = 0.40       # 1 IP chiếm >40% tổng traffic
PORT_SCAN_THRESH = 100           # Số port khác nhau bị scan


class DDoSDetector:

    def __init__(self):
        self._id = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, packets: List[PacketInfo]) -> Tuple[List[Alert], NetworkStats]:
        if not packets:
            return [], NetworkStats()

        stats = self._build_stats(packets)
        alerts: List[Alert] = []

        alerts += self._detect_syn_flood(packets, stats)
        alerts += self._detect_udp_flood(packets, stats)
        alerts += self._detect_icmp_flood(packets, stats)
        alerts += self._detect_http_flood(packets, stats)
        alerts += self._detect_volumetric(packets, stats)
        alerts += self._detect_single_source(packets, stats)
        alerts += self._detect_port_scan(packets, stats)

        # mark suspicious packets
        flagged = {pid for a in alerts for pid in a.evidence_packets}
        for p in packets:
            if p.number in flagged:
                p.is_suspicious = True

        order = {AlertSeverity.CRITICAL: 0, AlertSeverity.HIGH: 1,
                 AlertSeverity.MEDIUM: 2, AlertSeverity.LOW: 3}
        alerts.sort(key=lambda a: order.get(a.severity, 4))
        return alerts, stats

    # ── Statistics ────────────────────────────────────────────────────────────

    def _build_stats(self, packets: List[PacketInfo]) -> NetworkStats:
        s = NetworkStats()
        s.total_packets = len(packets)
        s.total_bytes = sum(p.length for p in packets)
        s.start_time = min(p.timestamp for p in packets)
        s.end_time = max(p.timestamp for p in packets)
        s.duration = max(s.end_time - s.start_time, 0.001)

        for p in packets:
            s.protocol_counts[p.protocol] = s.protocol_counts.get(p.protocol, 0) + 1
            s.src_ip_counts[p.src_ip] = s.src_ip_counts.get(p.src_ip, 0) + 1
            s.dst_ip_counts[p.dst_ip] = s.dst_ip_counts.get(p.dst_ip, 0) + 1

        bucket = 1.0
        n = max(1, int(s.duration / bucket) + 1)
        pps = [0] * n
        bps = [0] * n
        for p in packets:
            idx = min(int((p.timestamp - s.start_time) / bucket), n - 1)
            pps[idx] += 1
            bps[idx] += p.length
        s.packets_per_second = pps
        s.bytes_per_second = bps
        s.time_buckets = [s.start_time + i * bucket for i in range(n)]
        return s

    # ── Detectors ─────────────────────────────────────────────────────────────

    def _detect_syn_flood(self, packets, stats):
        alerts = []
        syns = [p for p in packets if p.flags.get("SYN") and not p.flags.get("ACK")]
        if not syns:
            return alerts

        by_src: Dict[str, List[PacketInfo]] = defaultdict(list)
        for p in syns:
            by_src[p.src_ip].append(p)

        for src_ip, pkts in by_src.items():
            rate = len(pkts) / stats.duration
            if rate < SYN_PER_SOURCE_THRESH:
                continue
            sev = (AlertSeverity.CRITICAL if rate > 300 else
                   AlertSeverity.HIGH if rate > 100 else AlertSeverity.MEDIUM)
            target = Counter(p.dst_ip for p in pkts).most_common(1)[0][0]
            alerts.append(Alert(
                id=self._nid(),
                attack_type=AttackType.SYN_FLOOD,
                severity=sev,
                description=(f"SYN Flood từ {src_ip} — {rate:.0f} SYN/s "
                             f"({len(pkts)} gói, không có ACK phản hồi)."),
                source_ips=[src_ip],
                target_ip=target,
                packet_count=len(pkts),
                rate=rate,
                start_time=pkts[0].timestamp,
                end_time=pkts[-1].timestamp,
                evidence_packets=[p.number for p in pkts[:200]],
                recommendation=(
                    "• Bật SYN Cookies trên server.\n"
                    "• Chặn IP nguồn trên Firewall.\n"
                    "• Cấu hình Rate Limiting cho kết nối TCP mới."
                ),
            ))

        total_rate = len(syns) / stats.duration
        if total_rate >= SYN_TOTAL_THRESH and len(by_src) > 3:
            alerts.append(Alert(
                id=self._nid(),
                attack_type=AttackType.SYN_FLOOD,
                severity=AlertSeverity.HIGH,
                description=(f"Distributed SYN Flood — {total_rate:.0f} SYN/s "
                             f"từ {len(by_src)} nguồn IP khác nhau."),
                source_ips=[ip for ip, _ in Counter({k: len(v) for k, v in by_src.items()}).most_common(10)],
                target_ip=None,
                packet_count=len(syns),
                rate=total_rate,
                start_time=syns[0].timestamp,
                end_time=syns[-1].timestamp,
                evidence_packets=[p.number for p in syns[:200]],
                recommendation=(
                    "• Triển khai IDS/IPS (Snort/Suricata) để chặn tự động.\n"
                    "• Sử dụng dịch vụ chống DDoS (Cloudflare, AWS Shield).\n"
                    "• Giới hạn connection rate theo subnet."
                ),
            ))
        return alerts

    def _detect_udp_flood(self, packets, stats):
        udps = [p for p in packets if p.protocol == "UDP"]
        if not udps:
            return []
        rate = len(udps) / stats.duration
        if rate < UDP_TOTAL_THRESH:
            return []
        sev = (AlertSeverity.CRITICAL if rate > 2000 else
               AlertSeverity.HIGH if rate > 1000 else AlertSeverity.MEDIUM)
        srcs = Counter(p.src_ip for p in udps)
        return [Alert(
            id=self._nid(),
            attack_type=AttackType.UDP_FLOOD,
            severity=sev,
            description=(f"UDP Flood — {rate:.0f} packet/s từ "
                         f"{len(srcs)} nguồn IP. Có thể bão hòa băng thông."),
            source_ips=[ip for ip, _ in srcs.most_common(5)],
            target_ip=Counter(p.dst_ip for p in udps).most_common(1)[0][0],
            packet_count=len(udps),
            rate=rate,
            start_time=udps[0].timestamp,
            end_time=udps[-1].timestamp,
            evidence_packets=[p.number for p in udps[:200]],
            recommendation=(
                "• Chặn UDP từ các IP không tin cậy trên Firewall.\n"
                "• Dùng Rate Limiting cho UDP traffic.\n"
                "• Kích hoạt tính năng chống UDP flood trên router."
            ),
        )]

    def _detect_icmp_flood(self, packets, stats):
        icmps = [p for p in packets if p.protocol == "ICMP"]
        if not icmps:
            return []
        rate = len(icmps) / stats.duration
        if rate < ICMP_TOTAL_THRESH:
            return []
        sev = AlertSeverity.HIGH if rate > 200 else AlertSeverity.MEDIUM
        srcs = Counter(p.src_ip for p in icmps)
        return [Alert(
            id=self._nid(),
            attack_type=AttackType.ICMP_FLOOD,
            severity=sev,
            description=(f"ICMP/Ping Flood — {rate:.0f} packet/s. "
                         f"Từ {len(srcs)} nguồn. Có thể là Smurf Attack."),
            source_ips=[ip for ip, _ in srcs.most_common(5)],
            target_ip=Counter(p.dst_ip for p in icmps).most_common(1)[0][0],
            packet_count=len(icmps),
            rate=rate,
            start_time=icmps[0].timestamp,
            end_time=icmps[-1].timestamp,
            evidence_packets=[p.number for p in icmps[:200]],
            recommendation=(
                "• Chặn ICMP echo-request từ bên ngoài trên Firewall.\n"
                "• Giới hạn ICMP rate (iptables -m limit).\n"
                "• Kiểm tra broadcast amplification (Smurf Attack)."
            ),
        )]

    def _detect_http_flood(self, packets, stats):
        alerts = []
        http_pkts = [p for p in packets if p.protocol in ("HTTP", "HTTPS")]
        if not http_pkts:
            return alerts
        by_src: Dict[str, List[PacketInfo]] = defaultdict(list)
        for p in http_pkts:
            by_src[p.src_ip].append(p)
        for src_ip, pkts in by_src.items():
            rate = len(pkts) / stats.duration
            if rate < HTTP_PER_SOURCE_THRESH:
                continue
            sev = AlertSeverity.HIGH if rate > 300 else AlertSeverity.MEDIUM
            alerts.append(Alert(
                id=self._nid(),
                attack_type=AttackType.HTTP_FLOOD,
                severity=sev,
                description=(f"HTTP Flood từ {src_ip} — {rate:.0f} req/s "
                             f"({len(pkts)} HTTP packets)."),
                source_ips=[src_ip],
                target_ip=Counter(p.dst_ip for p in pkts).most_common(1)[0][0],
                packet_count=len(pkts),
                rate=rate,
                start_time=pkts[0].timestamp,
                end_time=pkts[-1].timestamp,
                evidence_packets=[p.number for p in pkts[:200]],
                recommendation=(
                    "• Triển khai Web Application Firewall (WAF).\n"
                    "• Bật CAPTCHA cho request bất thường.\n"
                    "• Rate-limit HTTP requests theo IP (Nginx/HAProxy)."
                ),
            ))
        return alerts

    def _detect_volumetric(self, packets, stats):
        bw_mb = stats.total_bytes / stats.duration / 1_000_000
        if bw_mb < VOLUMETRIC_THRESH_MB:
            return []
        sev = (AlertSeverity.CRITICAL if bw_mb > 100 else
               AlertSeverity.HIGH if bw_mb > 20 else AlertSeverity.MEDIUM)
        srcs = Counter(p.src_ip for p in packets)
        return [Alert(
            id=self._nid(),
            attack_type=AttackType.VOLUMETRIC,
            severity=sev,
            description=(f"Tấn công Volumetric — Băng thông {bw_mb:.2f} MB/s "
                         f"vượt ngưỡng {VOLUMETRIC_THRESH_MB} MB/s."),
            source_ips=[ip for ip, _ in srcs.most_common(5)],
            target_ip=None,
            packet_count=stats.total_packets,
            rate=stats.avg_packet_rate,
            start_time=stats.start_time,
            end_time=stats.end_time,
            evidence_packets=[p.number for p in packets[:100]],
            recommendation=(
                "• Sử dụng CDN (Cloudflare, Akamai) để hấp thụ traffic.\n"
                "• Liên hệ ISP để null-route IP đích tạm thời.\n"
                "• Tăng băng thông hoặc dùng anycast routing."
            ),
        )]

    def _detect_single_source(self, packets, stats):
        if not packets:
            return []
        total = len(packets)
        alerts = []
        srcs = Counter(p.src_ip for p in packets)
        for src_ip, count in srcs.most_common(3):
            ratio = count / total
            if ratio < SINGLE_SOURCE_RATIO or count < 50:
                continue
            rate = count / stats.duration
            sev = AlertSeverity.HIGH if ratio > 0.7 else AlertSeverity.MEDIUM
            src_pkts = [p for p in packets if p.src_ip == src_ip]
            target = Counter(p.dst_ip for p in src_pkts).most_common(1)[0][0]
            alerts.append(Alert(
                id=self._nid(),
                attack_type=AttackType.SINGLE_SOURCE,
                severity=sev,
                description=(f"DoS đơn nguồn — {src_ip} chiếm "
                             f"{ratio*100:.1f}% traffic ({count}/{total} packets, {rate:.0f} pkt/s)."),
                source_ips=[src_ip],
                target_ip=target,
                packet_count=count,
                rate=rate,
                start_time=src_pkts[0].timestamp,
                end_time=src_pkts[-1].timestamp,
                evidence_packets=[p.number for p in src_pkts[:200]],
                recommendation=(
                    "• Chặn ngay IP nguồn trên Firewall.\n"
                    "• Thêm rule ACL trên router.\n"
                    "• Theo dõi hành vi IP này trong các phiên tiếp theo."
                ),
            ))
        return alerts

    def _detect_port_scan(self, packets, stats):
        # Only TCP packets are considered for port scan (real scanners use TCP SYN;
        # UDP floods hitting random ports are handled by _detect_udp_flood instead).
        tcp_pkts = [p for p in packets if p.protocol in ("TCP", "HTTP", "HTTPS")]

        pair_ports: Dict[Tuple[str, str], set] = defaultdict(set)
        pair_pkts:  Dict[Tuple[str, str], List[PacketInfo]] = defaultdict(list)
        for p in tcp_pkts:
            if p.dst_port is not None:
                key = (p.src_ip, p.dst_ip)
                pair_ports[key].add(p.dst_port)
                pair_pkts[key].append(p)

        # Per source IP, keep only the pair with the most ports scanned (avoid
        # UDP-flood sources generating dozens of near-identical port-scan alerts)
        best_pair: Dict[str, Tuple[str, int]] = {}   # src → (dst, port_count)
        for (src, dst), ports in pair_ports.items():
            if len(ports) >= PORT_SCAN_THRESH:
                if src not in best_pair or len(ports) > best_pair[src][1]:
                    best_pair[src] = (dst, len(ports))

        alerts = []
        for src, (dst, port_count) in best_pair.items():
            pkts = pair_pkts[(src, dst)]
            rate = len(pkts) / stats.duration
            sev = AlertSeverity.HIGH if port_count > 200 else AlertSeverity.MEDIUM
            alerts.append(Alert(
                id=self._nid(),
                attack_type=AttackType.PORT_SCAN,
                severity=sev,
                description=(f"Port Scan — {src} quét {port_count} port "
                             f"trên {dst} ({rate:.0f} pkt/s). Có thể là bước trinh sát trước tấn công."),
                source_ips=[src],
                target_ip=dst,
                packet_count=len(pkts),
                rate=rate,
                start_time=pkts[0].timestamp,
                end_time=pkts[-1].timestamp,
                evidence_packets=[p.number for p in pkts[:200]],
                recommendation=(
                    "• Chặn IP scanner trên Firewall.\n"
                    "• Tắt các port không cần thiết.\n"
                    "• Cài đặt honeypot để phát hiện sớm."
                ),
            ))
        return alerts

    def _nid(self) -> int:
        self._id += 1
        return self._id
