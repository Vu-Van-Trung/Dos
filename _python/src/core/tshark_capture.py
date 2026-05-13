"""
TShark real-time capture — chạy tshark subprocess và parse từng packet.
"""
import os
import re
import shutil
import subprocess
import logging
from typing import List, Optional

from PyQt5.QtCore import QThread, pyqtSignal

from .models import PacketInfo

logger = logging.getLogger(__name__)

# ── TShark location ──────────────────────────────────────────────────────────
_TSHARK_CANDIDATES = [
    "tshark",
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "/usr/bin/tshark",
    "/usr/local/bin/tshark",
    "/opt/homebrew/bin/tshark",
]

def find_tshark() -> Optional[str]:
    for p in _TSHARK_CANDIDATES:
        if shutil.which(p):
            return shutil.which(p)
        if os.path.isfile(p):
            return p
    return None


# ── Field list ───────────────────────────────────────────────────────────────
_SEP = "\x01"   # ASCII SOH — safe separator (never appears in field values)

_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "udp.srcport",
    "udp.dstport",
    "icmp.type",
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
    "frame.len",
]

_ICMP_NAMES = {0: "Echo Reply", 3: "Unreachable", 8: "Echo Request", 11: "TTL Exceeded"}


# ── Interface list ────────────────────────────────────────────────────────────
def get_interfaces(tshark_path: str) -> List[dict]:
    """Run ``tshark -D`` and return list of {index, name, description}."""
    try:
        result = subprocess.run(
            [tshark_path, "-D"],
            capture_output=True, text=True, timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        interfaces = []
        for line in result.stdout.splitlines():
            m = re.match(r"(\d+)\.\s+(.*)", line.strip())
            if m:
                name = m.group(2).strip()
                interfaces.append({
                    "index": int(m.group(1)),
                    "name": name,
                    "label": f"{m.group(1)}. {name}",
                })
        return interfaces
    except Exception as e:
        logger.error(f"tshark -D failed: {e}")
        return []


# ── Capture thread ────────────────────────────────────────────────────────────
class TSharkCapture(QThread):
    """Background thread that streams packets from tshark."""

    packet_received = pyqtSignal(object)   # PacketInfo
    stats_updated   = pyqtSignal(int, float)  # (packet_count, elapsed)
    status_changed  = pyqtSignal(str)
    error_occurred  = pyqtSignal(str)

    def __init__(
        self,
        tshark_path: str,
        interface: str,
        capture_filter: str = "",
        bpf_filter: str = "",
        max_packets: int = 0,
    ):
        super().__init__()
        self.tshark_path  = tshark_path
        self.interface    = interface
        self.capture_filter = capture_filter   # display filter  (-Y)
        self.bpf_filter   = bpf_filter          # capture filter  (-f)
        self.max_packets  = max_packets
        self._stop        = False
        self._proc: Optional[subprocess.Popen] = None
        self._counter     = 0

    # ── Public ────────────────────────────────────────────────────────────────

    def stop(self):
        self._stop = True
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except OSError:
                pass

    # ── Thread entry point ────────────────────────────────────────────────────

    def run(self):
        import time
        cmd = self._build_cmd()
        logger.info("TShark cmd: %s", " ".join(cmd))

        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                creationflags=flags,
            )
        except FileNotFoundError:
            self.error_occurred.emit(
                f"Không tìm thấy tshark tại: {self.tshark_path}\n"
                "Cài Wireshark/TShark rồi thử lại."
            )
            return
        except PermissionError:
            self.error_occurred.emit(
                "Lỗi quyền truy cập.\n"
                "Chạy ứng dụng với quyền Administrator (Windows)\n"
                "hoặc thêm user vào group 'wireshark' (Linux)."
            )
            return
        except Exception as e:
            self.error_occurred.emit(f"Không thể khởi động TShark: {e}")
            return

        self.status_changed.emit("Đang capture…")
        t_start = time.time()

        for raw_line in self._proc.stdout:
            if self._stop:
                break
            line = raw_line.rstrip("\n")
            if not line:
                continue

            pkt = self._parse(line)
            if pkt:
                self.packet_received.emit(pkt)
                if self._counter % 50 == 0:
                    self.stats_updated.emit(self._counter, time.time() - t_start)

            if self.max_packets and self._counter >= self.max_packets:
                break

        # Drain stderr for error messages
        try:
            _, stderr = self._proc.communicate(timeout=1)
            if stderr and not self._stop:
                for line in stderr.splitlines():
                    line = line.strip()
                    if line and not line.startswith("Capturing on"):
                        logger.warning("tshark stderr: %s", line)
        except subprocess.TimeoutExpired:
            self._proc.kill()

        self.status_changed.emit("Dừng")
        self.stats_updated.emit(self._counter, time.time() - t_start)

    # ── Command builder ───────────────────────────────────────────────────────

    def _build_cmd(self) -> List[str]:
        cmd = [
            self.tshark_path,
            "-i", self.interface,
            "-l",    # line-buffered
            "-n",    # no name resolution (faster)
        ]
        if self.bpf_filter:
            cmd += ["-f", self.bpf_filter]
        if self.capture_filter:
            cmd += ["-Y", self.capture_filter]
        if self.max_packets > 0:
            cmd += ["-c", str(self.max_packets)]

        cmd += [
            "-T", "fields",
            "-E", f"separator={_SEP}",
            "-E", "header=n",
            "-E", "quote=n",
            "-E", "occurrence=f",   # first value only for multi-valued fields
        ]
        for field in _FIELDS:
            cmd += ["-e", field]
        return cmd

    # ── Line parser ───────────────────────────────────────────────────────────

    def _parse(self, line: str) -> Optional[PacketInfo]:
        parts = line.split(_SEP)
        # Pad to expected length
        while len(parts) < len(_FIELDS):
            parts.append("")

        (
            frame_no, time_epoch, ip_src, ip_dst, ip_proto,
            tcp_sport, tcp_dport, tcp_flags,
            udp_sport, udp_dport,
            icmp_type,
            arp_src, arp_dst,
            frame_len,
        ) = parts[:14]

        self._counter += 1

        src_ip   = ip_src  or arp_src  or "0.0.0.0"
        dst_ip   = ip_dst  or arp_dst  or "0.0.0.0"
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        protocol = "OTHER"
        flags: dict = {}
        info = ""

        try:
            ts     = float(time_epoch) if time_epoch else 0.0
            length = int(frame_len)    if frame_len  else 0
            proto  = int(ip_proto)     if ip_proto   else None

            if proto == 6:  # TCP
                src_port = int(tcp_sport) if tcp_sport else None
                dst_port = int(tcp_dport) if tcp_dport else None

                if tcp_flags:
                    # TShark outputs hex like "0x00000002"
                    fv = int(tcp_flags, 16)
                    flags = {
                        "SYN": bool(fv & 0x02),
                        "ACK": bool(fv & 0x10),
                        "FIN": bool(fv & 0x01),
                        "RST": bool(fv & 0x04),
                        "PSH": bool(fv & 0x08),
                        "URG": bool(fv & 0x20),
                    }

                if dst_port == 80  or src_port == 80:   protocol = "HTTP"
                elif dst_port == 443 or src_port == 443: protocol = "HTTPS"
                elif dst_port == 53  or src_port == 53:  protocol = "DNS"
                else:                                    protocol = "TCP"

                fs = " ".join(k for k, v in flags.items() if v)
                info = f"{src_port} → {dst_port} [{fs}]"

            elif proto == 17:  # UDP
                src_port = int(udp_sport) if udp_sport else None
                dst_port = int(udp_dport) if udp_dport else None
                protocol = "DNS" if (dst_port == 53 or src_port == 53) else "UDP"
                info = f"{src_port} → {dst_port}"

            elif proto == 1:   # ICMP
                protocol = "ICMP"
                if icmp_type:
                    info = _ICMP_NAMES.get(int(icmp_type), f"Type {icmp_type}")

            elif not ip_proto and (arp_src or arp_dst):  # ARP
                protocol = "ARP"
                info = f"ARP {arp_src} → {arp_dst}"

            return PacketInfo(
                number=self._counter,
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=length,
                flags=flags,
                info=info,
            )

        except Exception as e:
            logger.debug("Parse error on line %r: %s", line[:80], e)
            return None
