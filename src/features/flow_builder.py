import time
from collections import defaultdict
from src.utils.logger import setup_logger

logger = setup_logger("flow_builder")

class FlowBuilder:

    def __init__(self, flow_timeout: int = 60):
        self.flow_timeout = flow_timeout
        self.flows = defaultdict(list)
        self.flow_stats = {}

    def _get_flow_key(self, packet: dict) -> str:
        src_ip = packet.get("src_ip", "0.0.0.0")
        dst_ip = packet.get("dst_ip", "0.0.0.0")
        src_port = packet.get("src_port", 0)
        dst_port = packet.get("dst_port", 0)
        protocol = packet.get("transport", "UNKNOWN")
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"

    def add_packet(self, packet: dict):
        try:
            flow_key = self._get_flow_key(packet)
            self.flows[flow_key].append(packet)
            self._update_flow_stats(flow_key, packet)
        except Exception as e:
            logger.error(f"Error adding packet to flow: {e}")

    def _update_flow_stats(self, flow_key: str, packet: dict):
        if flow_key not in self.flow_stats:
            self.flow_stats[flow_key] = {
                "flow_key": flow_key,
                "start_time": time.time(),
                "last_time": time.time(),
                "packet_count": 0,
                "total_bytes": 0,
                "max_length": 0,
                "min_length": float("inf"),
                "src_ip": packet.get("src_ip", ""),
                "dst_ip": packet.get("dst_ip", ""),
                "src_port": packet.get("src_port", 0),
                "dst_port": packet.get("dst_port", 0),
                "protocol": packet.get("transport", ""),
                "syn_count": 0,
                "ack_count": 0,
                "fin_count": 0,
                "rst_count": 0,
            }

        stats = self.flow_stats[flow_key]
        length = packet.get("length", 0)

        stats["packet_count"] += 1
        stats["total_bytes"] += length
        stats["last_time"] = time.time()
        stats["max_length"] = max(stats["max_length"], length)
        stats["min_length"] = min(stats["min_length"], length)

        # Count TCP flags
        tcp_flags = packet.get("tcp_flags", "0x000")
        try:
            flags_int = int(tcp_flags, 16)
            if flags_int & 0x02:
                stats["syn_count"] += 1
            if flags_int & 0x10:
                stats["ack_count"] += 1
            if flags_int & 0x01:
                stats["fin_count"] += 1
            if flags_int & 0x04:
                stats["rst_count"] += 1
        except Exception:
            pass

    def get_flow_features(self, flow_key: str) -> dict:
        stats = self.flow_stats.get(flow_key, {})
        if not stats:
            return {}

        duration = stats["last_time"] - stats["start_time"]
        packet_count = stats["packet_count"]

        return {
            "flow_duration": duration,
            "packet_count": packet_count,
            "total_bytes": stats["total_bytes"],
            "avg_packet_size": stats["total_bytes"] / max(packet_count, 1),
            "max_packet_size": stats["max_length"],
            "min_packet_size": stats["min_length"] if stats["min_length"] != float("inf") else 0,
            "packets_per_second": packet_count / max(duration, 0.001),
            "bytes_per_second": stats["total_bytes"] / max(duration, 0.001),
            "syn_count": stats["syn_count"],
            "ack_count": stats["ack_count"],
            "fin_count": stats["fin_count"],
            "rst_count": stats["rst_count"],
            "src_ip": stats["src_ip"],
            "dst_ip": stats["dst_ip"],
            "src_port": stats["src_port"],
            "dst_port": stats["dst_port"],
            "protocol": stats["protocol"],
        }

    def get_expired_flows(self) -> list:
        expired = []
        current_time = time.time()
        for flow_key, stats in list(self.flow_stats.items()):
            if current_time - stats["last_time"] > self.flow_timeout:
                expired.append(self.get_flow_features(flow_key))
                del self.flow_stats[flow_key]
                del self.flows[flow_key]
        return expired

    def get_active_flow_count(self) -> int:
        return len(self.flows)
