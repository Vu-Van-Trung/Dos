from dataclasses import dataclass, field
from typing import Optional, Dict, List
from enum import Enum


class AlertSeverity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackType(Enum):
    SYN_FLOOD = "SYN Flood"
    UDP_FLOOD = "UDP Flood"
    ICMP_FLOOD = "ICMP/Ping Flood"
    HTTP_FLOOD = "HTTP Flood"
    VOLUMETRIC = "Volumetric Attack"
    SINGLE_SOURCE = "Single Source DoS"
    PORT_SCAN = "Port Scan"
    NORMAL = "Normal Traffic"


@dataclass
class PacketInfo:
    number: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int
    flags: Dict[str, bool] = field(default_factory=dict)
    info: str = ""
    is_suspicious: bool = False

    @property
    def time_str(self) -> str:
        return f"{self.timestamp:.6f}"

    @property
    def flags_str(self) -> str:
        if not self.flags:
            return ""
        return " ".join(k for k, v in self.flags.items() if v)


@dataclass
class Alert:
    id: int
    attack_type: AttackType
    severity: AlertSeverity
    description: str
    source_ips: List[str]
    target_ip: Optional[str]
    packet_count: int
    rate: float
    start_time: float
    end_time: float
    evidence_packets: List[int] = field(default_factory=list)
    recommendation: str = ""

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def severity_color(self) -> str:
        return {
            AlertSeverity.LOW:      "#F9E64F",
            AlertSeverity.MEDIUM:   "#FAB387",
            AlertSeverity.HIGH:     "#F38BA8",
            AlertSeverity.CRITICAL: "#D20F39",
        }.get(self.severity, "#CDD6F4")

    @property
    def severity_bg(self) -> str:
        return {
            AlertSeverity.LOW:      "#3D3929",
            AlertSeverity.MEDIUM:   "#3D2B1A",
            AlertSeverity.HIGH:     "#3D1A1F",
            AlertSeverity.CRITICAL: "#4D0F0F",
        }.get(self.severity, "#313244")


@dataclass
class NetworkStats:
    total_packets: int = 0
    total_bytes: int = 0
    duration: float = 0.0
    start_time: float = 0.0
    end_time: float = 0.0
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    src_ip_counts: Dict[str, int] = field(default_factory=dict)
    dst_ip_counts: Dict[str, int] = field(default_factory=dict)
    packets_per_second: List[float] = field(default_factory=list)
    bytes_per_second: List[float] = field(default_factory=list)
    time_buckets: List[float] = field(default_factory=list)

    @property
    def avg_packet_rate(self) -> float:
        return self.total_packets / self.duration if self.duration > 0 else 0.0

    @property
    def avg_bandwidth_mbps(self) -> float:
        return (self.total_bytes / self.duration / 1_000_000) if self.duration > 0 else 0.0

    @property
    def max_pps(self) -> float:
        return max(self.packets_per_second) if self.packets_per_second else 0.0
