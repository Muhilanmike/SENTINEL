import os
import tempfile
from unittest.mock import patch
from src.engine.rule_generator import SnortRuleGenerator


class TestSnortRuleGenerator:

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.rules_path = os.path.join(self.tmpdir, "rules", "local.rules")
        with patch.object(SnortRuleGenerator, "__init__", lambda self_: None):
            self.gen = SnortRuleGenerator()
        self.gen.rules_path = self.rules_path
        self.gen.generated_rules = []
        self.gen.blocked_ips = set()
        self.gen.sid_counter = 2000000

    def test_generate_ip_block_rule(self):
        rule = self.gen.generate_ip_block_rule("10.0.0.1", "CRITICAL", "SYN Flood")
        assert rule is not None
        assert "10.0.0.1" in rule
        assert "SENTINEL-ML" in rule
        assert "SYN Flood" in rule

    def test_duplicate_ip_block_returns_none(self):
        self.gen.generate_ip_block_rule("10.0.0.1", "CRITICAL", "SYN Flood")
        rule = self.gen.generate_ip_block_rule("10.0.0.1", "CRITICAL", "SYN Flood")
        assert rule is None

    def test_generate_port_rule(self):
        rule = self.gen.generate_port_rule(22, "TCP", "SSH Brute Force")
        assert "22" in rule
        assert "tcp" in rule
        assert "threshold" in rule

    def test_process_alert_critical(self):
        alert = {
            "is_threat": True,
            "severity": "CRITICAL",
            "attack_type": "SYN Flood",
            "src_ip": "10.0.0.1",
            "dst_port": 80,
            "protocol": "TCP",
        }
        rule = self.gen.process_alert(alert)
        assert rule is not None
        assert os.path.exists(self.rules_path)

    def test_process_alert_high(self):
        alert = {
            "is_threat": True,
            "severity": "HIGH",
            "attack_type": "Web Attack",
            "src_ip": "10.0.0.1",
            "dst_port": 443,
            "protocol": "TCP",
        }
        rule = self.gen.process_alert(alert)
        assert rule is not None
        assert "443" in rule

    def test_process_non_threat_returns_none(self):
        alert = {"is_threat": False, "severity": "NORMAL"}
        assert self.gen.process_alert(alert) is None

    def test_sid_increments(self):
        self.gen.generate_port_rule(80, "TCP", "Test1")
        self.gen.generate_port_rule(443, "TCP", "Test2")
        assert self.gen.sid_counter == 2000002

    def test_get_generated_count(self):
        alert = {
            "is_threat": True,
            "severity": "HIGH",
            "attack_type": "Test",
            "dst_port": 80,
            "protocol": "TCP",
        }
        self.gen.process_alert(alert)
        assert self.gen.get_generated_count() == 1
