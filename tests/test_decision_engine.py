import pytest
from unittest.mock import MagicMock, patch
from src.engine.decision_engine import DecisionEngine


class TestWhitelist:

    def setup_method(self):
        self.engine = DecisionEngine()

    def test_whitelisted_src_ip(self, sample_mdns_packet):
        result = self.engine.analyze(sample_mdns_packet)
        assert result["severity"] == "NORMAL"
        assert result["is_threat"] is False

    def test_whitelisted_dst_ip(self, sample_upnp_packet):
        result = self.engine.analyze(sample_upnp_packet)
        assert result["severity"] == "NORMAL"
        assert result["is_threat"] is False

    def test_whitelisted_dst_port(self):
        packet = {
            "src_ip": "10.10.10.10",
            "dst_ip": "10.10.10.20",
            "dst_port": 5353,
            "src_port": 40000,
            "transport": "UDP",
        }
        result = self.engine.analyze(packet)
        assert result["severity"] == "NORMAL"

    def test_multicast_range_whitelisted(self, sample_multicast_packet):
        """224.0.0.100 is not explicitly listed but falls in 224.0.0.0/4."""
        result = self.engine.analyze(sample_multicast_packet)
        assert result["severity"] == "NORMAL"
        assert result["is_threat"] is False

    def test_non_whitelisted_passes_through(self, sample_tcp_packet):
        """Non-whitelisted packet should go through ML analysis."""
        result = self.engine.analyze(sample_tcp_packet)
        # Should have ML fields (may or may not be threat depending on model)
        assert "severity" in result


class TestSeverityDetermination:

    def setup_method(self):
        self.engine = DecisionEngine()

    def test_critical_requires_high_confidence(self):
        rf = {"is_attack": True, "confidence": 0.95}
        if_ = {"is_anomaly": True, "anomaly_score": -0.5}
        assert self.engine._determine_severity(rf, if_) == "CRITICAL"

    def test_no_critical_on_low_confidence(self):
        rf = {"is_attack": True, "confidence": 0.72}
        if_ = {"is_anomaly": True, "anomaly_score": -0.5}
        # Should be HIGH, not CRITICAL (confidence < 0.9)
        assert self.engine._determine_severity(rf, if_) == "HIGH"

    def test_medium_attack_only(self):
        rf = {"is_attack": True, "confidence": 0.75}
        if_ = {"is_anomaly": False, "anomaly_score": 0.1}
        assert self.engine._determine_severity(rf, if_) == "MEDIUM"

    def test_low_anomaly_only(self):
        rf = {"is_attack": False, "confidence": 0.3}
        if_ = {"is_anomaly": True, "anomaly_score": -0.5}
        assert self.engine._determine_severity(rf, if_) == "LOW"

    def test_normal_neither(self):
        rf = {"is_attack": False, "confidence": 0.2}
        if_ = {"is_anomaly": False, "anomaly_score": 0.1}
        assert self.engine._determine_severity(rf, if_) == "NORMAL"

    def test_high_attack_very_confident_no_anomaly(self):
        rf = {"is_attack": True, "confidence": 0.95}
        if_ = {"is_anomaly": False, "anomaly_score": 0.0}
        assert self.engine._determine_severity(rf, if_) == "HIGH"


class TestAttackType:

    def setup_method(self):
        self.engine = DecisionEngine()

    def test_syn_flood(self):
        packet = {"dst_port": 80, "tcp_flags": "0x002"}
        assert self.engine._determine_attack_type(packet, {}) == "SYN Flood"

    def test_ssh_brute_force(self):
        packet = {"dst_port": 22, "tcp_flags": "0x018"}
        assert self.engine._determine_attack_type(packet, {}) == "SSH Brute Force"

    def test_web_attack(self):
        packet = {"dst_port": 443, "tcp_flags": "0x018"}
        assert self.engine._determine_attack_type(packet, {}) == "Web Attack"

    def test_dns_attack(self):
        packet = {"dst_port": 53, "tcp_flags": "0x000"}
        assert self.engine._determine_attack_type(packet, {}) == "DNS Attack"

    def test_rdp_attack(self):
        packet = {"dst_port": 3389, "tcp_flags": "0x018"}
        assert self.engine._determine_attack_type(packet, {}) == "RDP Attack"

    def test_fallback_to_rf_label(self):
        packet = {"dst_port": 9999, "tcp_flags": "0x018"}
        rf_result = {"label": "Port Scan"}
        assert self.engine._determine_attack_type(packet, rf_result) == "Port Scan"
