import ipaddress
import numpy as np
from datetime import datetime
from src.ml.random_forest_model import RandomForestModel
from src.ml.isolation_forest_model import IsolationForestModel
from src.features.feature_extractor import FeatureExtractor
from src.utils.logger import setup_logger
from src.utils.config import config

logger = setup_logger("decision_engine")


def _load_whitelist():
    ips = set(config.get("whitelist", "ips", default=[]))
    ports = set(config.get("whitelist", "ports", default=[]))
    ip_networks = []
    for cidr in config.get("whitelist", "ip_ranges", default=[]):
        try:
            ip_networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            logger.warning(f"Invalid whitelist CIDR: {cidr}")
    return ips, ports, ip_networks


class DecisionEngine:

    def __init__(self):
        self.rf_model = RandomForestModel()
        self.if_model = IsolationForestModel()
        self.feature_extractor = FeatureExtractor()
        self.rf_threshold = config.get("ml", "threshold", "rf_confidence", default=0.7)
        self.if_threshold = config.get("ml", "threshold", "if_anomaly_score", default=-0.1)
        self.whitelist_ips, self.whitelist_ports, self.whitelist_networks = _load_whitelist()

    def load_models(self):
        rf_loaded = self.rf_model.load()
        if_loaded = self.if_model.load()
        logger.info(f"Models loaded - RF: {rf_loaded}, IF: {if_loaded}")
        return rf_loaded, if_loaded

    def _is_whitelisted_ip(self, ip: str) -> bool:
        if ip in self.whitelist_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            for network in self.whitelist_networks:
                if addr in network:
                    return True
        except ValueError:
            pass
        return False

    def _is_whitelisted(self, src_ip: str, dst_ip: str, dst_port: int) -> str:
        """Returns reason string if whitelisted, empty string if not."""
        if self._is_whitelisted_ip(src_ip):
            return f"src_ip {src_ip} whitelisted"
        if self._is_whitelisted_ip(dst_ip):
            return f"dst_ip {dst_ip} whitelisted"
        if dst_port in self.whitelist_ports:
            return f"dst_port {dst_port} whitelisted"
        return ""

    def _determine_severity(self, rf_result: dict, if_result: dict) -> str:
        is_attack = rf_result.get("is_attack", False)
        is_anomaly = if_result.get("is_anomaly", False)
        confidence = rf_result.get("confidence", 0.0)
        anomaly_score = if_result.get("anomaly_score", 0.0)

        if is_attack and confidence >= 0.9 and is_anomaly:
            return "CRITICAL"
        elif is_attack and confidence >= 0.7 and is_anomaly:
            return "HIGH"
        elif is_attack and confidence >= 0.9:
            return "HIGH"
        elif is_attack and confidence >= 0.7:
            return "MEDIUM"
        elif is_anomaly and anomaly_score <= -0.3:
            return "LOW"
        elif is_anomaly:
            return "LOW"
        else:
            return "NORMAL"

    def _determine_attack_type(self, packet: dict, rf_result: dict) -> str:
        dst_port = packet.get("dst_port", 0)
        tcp_flags = packet.get("tcp_flags", "0x000")

        try:
            flags_int = int(tcp_flags, 16)
            syn = flags_int & 0x02
            ack = flags_int & 0x10
            rst = flags_int & 0x04
            if syn and not ack:
                return "SYN Flood"
            if rst:
                return "RST Attack"
        except Exception:
            pass

        if dst_port == 22:
            return "SSH Brute Force"
        elif dst_port in [80, 443]:
            return "Web Attack"
        elif dst_port == 53:
            return "DNS Attack"
        elif dst_port == 21:
            return "FTP Attack"
        elif dst_port == 3389:
            return "RDP Attack"

        return rf_result.get("label", "Unknown Attack")

    def analyze(self, packet: dict) -> dict:
        try:
            src_ip = packet.get("src_ip", "")
            dst_ip = packet.get("dst_ip", "")
            dst_port = packet.get("dst_port", 0)

            whitelist_reason = self._is_whitelisted(src_ip, dst_ip, dst_port)
            if whitelist_reason:
                logger.debug(f"Whitelisted: {whitelist_reason} ({src_ip} -> {dst_ip}:{dst_port})")
                return {
                    "severity": "NORMAL",
                    "is_threat": False,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": packet.get("src_port", 0),
                    "dst_port": dst_port,
                    "protocol": packet.get("transport", ""),
                    "attack_type": "NONE",
                }

            features = self.feature_extractor.extract(packet)
            rf_result = self.rf_model.predict(features)
            if_result = self.if_model.predict(features)
            severity = self._determine_severity(rf_result, if_result)
            is_threat = severity != "NORMAL"

            result = {
                "timestamp": datetime.now().isoformat(),
                "severity": severity,
                "is_threat": is_threat,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": packet.get("src_port", 0),
                "dst_port": dst_port,
                "protocol": packet.get("transport", ""),
                "rf_label": rf_result.get("label", "UNKNOWN"),
                "rf_confidence": rf_result.get("confidence", 0.0),
                "if_label": if_result.get("label", "UNKNOWN"),
                "if_anomaly_score": if_result.get("anomaly_score", 0.0),
                "attack_type": "NONE"
            }

            if is_threat:
                result["attack_type"] = self._determine_attack_type(
                    packet, rf_result
                )
                logger.warning(
                    f"THREAT DETECTED [{severity}] "
                    f"{result['attack_type']} "
                    f"from {src_ip} -> {dst_ip}"
                )

            return result

        except Exception as e:
            logger.error(f"Decision engine error: {e}")
            return {"severity": "ERROR", "is_threat": False}

    def analyze_batch(self, packets: list) -> list:
        return [self.analyze(p) for p in packets]
