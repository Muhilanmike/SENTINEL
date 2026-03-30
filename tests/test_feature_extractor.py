import numpy as np
from src.features.feature_extractor import FeatureExtractor


class TestFeatureExtractor:

    def setup_method(self):
        self.extractor = FeatureExtractor()

    def test_extract_tcp_packet(self, sample_tcp_packet):
        features = self.extractor.extract(sample_tcp_packet)
        assert isinstance(features, np.ndarray)
        assert len(features) == 17
        assert features[0] == 64.0   # packet_length
        assert features[1] == 64.0   # ttl
        assert features[4] == 1.0    # is_tcp
        assert features[5] == 0.0    # is_udp
        assert features[7] == 1.0    # is_http (port 80)

    def test_extract_udp_packet(self, sample_udp_packet):
        features = self.extractor.extract(sample_udp_packet)
        assert features[4] == 0.0    # is_tcp
        assert features[5] == 1.0    # is_udp
        assert features[9] == 1.0    # is_dns (port 53)

    def test_extract_tcp_flags(self, sample_syn_flood_packet):
        features = self.extractor.extract(sample_syn_flood_packet)
        assert features[12] == 1.0   # tcp_flag_syn
        assert features[13] == 0.0   # tcp_flag_ack

    def test_extract_batch(self, sample_tcp_packet, sample_udp_packet):
        batch = self.extractor.extract_batch([sample_tcp_packet, sample_udp_packet])
        assert batch.shape == (2, 17)

    def test_extract_empty_packet(self):
        features = self.extractor.extract({})
        assert len(features) == 17
        assert all(f == 0.0 for f in features)

    def test_feature_names(self):
        names = self.extractor.get_feature_names()
        assert len(names) == 17
        assert "packet_length" in names
        assert "tcp_flag_syn" in names

    def test_ssh_detection(self):
        packet = {"dst_port": 22, "transport": "TCP", "length": 100, "ttl": 64, "tcp_flags": "0x000"}
        features = self.extractor.extract(packet)
        assert features[10] == 1.0   # is_ssh

    def test_to_dataframe(self, sample_tcp_packet):
        df = self.extractor.to_dataframe([sample_tcp_packet])
        assert len(df) == 1
        assert list(df.columns) == self.extractor.feature_columns
