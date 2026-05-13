import logging
import os
from typing import List, Optional, Callable

from .models import PacketInfo
from .packet_processor import PacketProcessor

logger = logging.getLogger(__name__)

try:
    from scapy.all import PcapReader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PCAPLoader:

    def __init__(self):
        self.processor = PacketProcessor()

    def load(
        self,
        filepath: str,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> List[PacketInfo]:
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy chưa được cài đặt.\n"
                "Chạy lệnh: pip install scapy"
            )
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Không tìm thấy file: {filepath}")

        self.processor.reset()
        packets: List[PacketInfo] = []

        # Count total for progress
        total = 0
        try:
            with PcapReader(filepath) as rdr:
                for _ in rdr:
                    total += 1
        except Exception:
            total = 0

        with PcapReader(filepath) as rdr:
            for i, raw in enumerate(rdr):
                try:
                    pkt = self.processor.process(raw, float(raw.time))
                    if pkt:
                        packets.append(pkt)
                except Exception as e:
                    logger.debug(f"Skip packet {i}: {e}")
                    continue
                if progress_cb and (i % 200 == 0 or i == total - 1):
                    progress_cb(i + 1, max(total, i + 1))

        if progress_cb:
            progress_cb(total, total)

        logger.info(f"Loaded {len(packets)} packets from {filepath}")
        return packets
