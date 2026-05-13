import logging
from typing import Optional

from .models import PacketInfo

logger = logging.getLogger(__name__)

try:
    from scapy.all import IP, TCP, UDP, ICMP, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketProcessor:

    def __init__(self):
        self._counter = 0

    def reset(self):
        self._counter = 0

    def process(self, raw_pkt, timestamp: float = 0.0) -> Optional[PacketInfo]:
        if not SCAPY_AVAILABLE:
            return None
        try:
            self._counter += 1
            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            src_port: Optional[int] = None
            dst_port: Optional[int] = None
            protocol = "OTHER"
            flags: dict = {}
            info = ""

            if IP in raw_pkt:
                src_ip = raw_pkt[IP].src
                dst_ip = raw_pkt[IP].dst

                if TCP in raw_pkt:
                    tcp = raw_pkt[TCP]
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    f = tcp.flags
                    flags = {
                        "SYN": bool(f & 0x02),
                        "ACK": bool(f & 0x10),
                        "FIN": bool(f & 0x01),
                        "RST": bool(f & 0x04),
                        "PSH": bool(f & 0x08),
                        "URG": bool(f & 0x20),
                    }
                    flag_str = " ".join(k for k, v in flags.items() if v)
                    if dst_port == 80 or src_port == 80:
                        protocol = "HTTP"
                    elif dst_port == 443 or src_port == 443:
                        protocol = "HTTPS"
                    elif dst_port == 53 or src_port == 53:
                        protocol = "DNS"
                    else:
                        protocol = "TCP"
                    info = f"{src_port} → {dst_port} [{flag_str}]"

                elif UDP in raw_pkt:
                    udp = raw_pkt[UDP]
                    src_port = udp.sport
                    dst_port = udp.dport
                    protocol = "DNS" if dst_port == 53 or src_port == 53 else "UDP"
                    info = f"{src_port} → {dst_port}"

                elif ICMP in raw_pkt:
                    protocol = "ICMP"
                    icmp_names = {0: "Echo Reply", 3: "Unreachable",
                                  8: "Echo Request", 11: "TTL Exceeded"}
                    info = icmp_names.get(raw_pkt[ICMP].type, f"Type {raw_pkt[ICMP].type}")

                else:
                    protocol = f"IP/{raw_pkt[IP].proto}"

            elif ARP in raw_pkt:
                arp = raw_pkt[ARP]
                protocol = "ARP"
                src_ip = arp.psrc
                dst_ip = arp.pdst
                info = "Request" if arp.op == 1 else "Reply"

            return PacketInfo(
                number=self._counter,
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=len(raw_pkt),
                flags=flags,
                info=info,
            )
        except Exception as e:
            logger.debug(f"Packet #{self._counter} parse error: {e}")
            return None
