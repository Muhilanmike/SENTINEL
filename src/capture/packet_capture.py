import pyshark
import threading
import queue
from datetime import datetime
from src.utils.logger import setup_logger
from src.utils.config import config

logger = setup_logger("packet_capture")

class PacketCapture:

    def __init__(self):
        self.interface = config.get("network", "interface", default="eth0")
        self.bpf_filter = config.get("network", "bpf_filter", default="ip")
        self.max_packets = config.get("network", "max_packets", default=10000)
        self.packet_queue = queue.Queue(maxsize=5000)
        self.is_running = False
        self._capture_thread = None

    def _process_packet(self, packet):
        try:
            packet_info = {
                "timestamp": datetime.now().isoformat(),
                "length": int(packet.length),
                "protocol": packet.highest_layer,
            }

            if hasattr(packet, "ip"):
                packet_info["src_ip"] = packet.ip.src
                packet_info["dst_ip"] = packet.ip.dst
                packet_info["ttl"] = int(packet.ip.ttl)

            if hasattr(packet, "tcp"):
                packet_info["src_port"] = int(packet.tcp.srcport)
                packet_info["dst_port"] = int(packet.tcp.dstport)
                packet_info["tcp_flags"] = packet.tcp.flags
                packet_info["transport"] = "TCP"

            elif hasattr(packet, "udp"):
                packet_info["src_port"] = int(packet.udp.srcport)
                packet_info["dst_port"] = int(packet.udp.dstport)
                packet_info["transport"] = "UDP"

            if not self.packet_queue.full():
                self.packet_queue.put(packet_info)

        except Exception as e:
            logger.warning(f"Error processing packet: {e}")

    def _capture_loop(self):
        logger.info(f"Starting capture on interface: {self.interface}")
        try:
            capture = pyshark.LiveCapture(
                interface=self.interface,
                bpf_filter=self.bpf_filter
            )
            for packet in capture.sniff_continuously():
                if not self.is_running:
                    break
                self._process_packet(packet)

        except Exception as e:
            logger.error(f"Capture error: {e}")
            self.is_running = False

    def start(self):
        if self.is_running:
            logger.warning("Capture already running")
            return
        self.is_running = True
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True
        )
        self._capture_thread.start()
        logger.info("Packet capture started")

    def stop(self):
        self.is_running = False
        logger.info("Packet capture stopped")

    def get_packet(self, timeout=1):
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_queue_size(self):
        return self.packet_queue.qsize()
