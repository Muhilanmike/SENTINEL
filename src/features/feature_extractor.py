import numpy as np
import pandas as pd
from src.utils.logger import setup_logger

logger = setup_logger("feature_extractor")

class FeatureExtractor:

    def __init__(self):
        self.feature_columns = [
            "packet_length",
            "ttl",
            "src_port",
            "dst_port",
            "is_tcp",
            "is_udp",
            "is_icmp",
            "is_http",
            "is_https",
            "is_dns",
            "is_ssh",
            "is_ftp",
            "tcp_flag_syn",
            "tcp_flag_ack",
            "tcp_flag_fin",
            "tcp_flag_rst",
            "tcp_flag_psh",
        ]

    def extract(self, packet: dict) -> np.ndarray:
        try:
            features = {col: 0.0 for col in self.feature_columns}

            # Basic features
            features["packet_length"] = float(packet.get("length", 0))
            features["ttl"] = float(packet.get("ttl", 0))
            features["src_port"] = float(packet.get("src_port", 0))
            features["dst_port"] = float(packet.get("dst_port", 0))

            # Protocol flags
            transport = packet.get("transport", "")
            features["is_tcp"] = 1.0 if transport == "TCP" else 0.0
            features["is_udp"] = 1.0 if transport == "UDP" else 0.0

            protocol = packet.get("protocol", "").upper()
            features["is_icmp"] = 1.0 if "ICMP" in protocol else 0.0
            features["is_http"] = 1.0 if packet.get("dst_port") == 80 else 0.0
            features["is_https"] = 1.0 if packet.get("dst_port") == 443 else 0.0
            features["is_dns"] = 1.0 if packet.get("dst_port") == 53 else 0.0
            features["is_ssh"] = 1.0 if packet.get("dst_port") == 22 else 0.0
            features["is_ftp"] = 1.0 if packet.get("dst_port") == 21 else 0.0

            # TCP flags
            tcp_flags = packet.get("tcp_flags", "0x000")
            try:
                flags_int = int(tcp_flags, 16)
                features["tcp_flag_fin"] = 1.0 if flags_int & 0x01 else 0.0
                features["tcp_flag_syn"] = 1.0 if flags_int & 0x02 else 0.0
                features["tcp_flag_rst"] = 1.0 if flags_int & 0x04 else 0.0
                features["tcp_flag_psh"] = 1.0 if flags_int & 0x08 else 0.0
                features["tcp_flag_ack"] = 1.0 if flags_int & 0x10 else 0.0
            except Exception:
                pass

            return np.array([features[col] for col in self.feature_columns])

        except Exception as e:
            logger.error(f"Feature extraction error: {e}")
            return np.zeros(len(self.feature_columns))

    def extract_batch(self, packets: list) -> np.ndarray:
        features = [self.extract(p) for p in packets]
        return np.array(features)

    def to_dataframe(self, packets: list) -> pd.DataFrame:
        features = self.extract_batch(packets)
        return pd.DataFrame(features, columns=self.feature_columns)

    def get_feature_names(self) -> list:
        return self.feature_columns
