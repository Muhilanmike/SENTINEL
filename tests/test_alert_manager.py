import os
import tempfile
from unittest.mock import patch
from src.engine.alert_manager import AlertManager


class TestAlertManager:

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.log_path = os.path.join(self.tmpdir, "test_alerts.log")
        with patch.object(AlertManager, "__init__", lambda self_: None):
            self.manager = AlertManager()
        self.manager.alert_log = self.log_path
        self.manager.alert_history = []
        self.manager.alert_counts = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NORMAL": 0
        }
        import threading
        self.manager._lock = threading.Lock()

    def test_process_normal_increments_count(self):
        result = {"severity": "NORMAL", "is_threat": False}
        self.manager.process_alert(result)
        assert self.manager.alert_counts["NORMAL"] == 1
        assert len(self.manager.alert_history) == 0

    def test_process_threat_adds_to_history(self):
        result = {
            "severity": "HIGH",
            "is_threat": True,
            "attack_type": "SSH Brute Force",
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.1",
            "src_port": 12345,
            "dst_port": 22,
            "protocol": "TCP",
            "rf_label": "ATTACK",
            "rf_confidence": 0.85,
            "if_anomaly_score": -0.3,
        }
        self.manager.process_alert(result)
        assert len(self.manager.alert_history) == 1
        assert self.manager.alert_counts["HIGH"] == 1
        assert self.manager.alert_history[0]["attack_type"] == "SSH Brute Force"

    def test_alert_saved_to_file(self):
        result = {
            "severity": "CRITICAL",
            "is_threat": True,
            "attack_type": "SYN Flood",
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.1",
        }
        self.manager.process_alert(result)
        assert os.path.exists(self.log_path)
        with open(self.log_path) as f:
            content = f.read()
        assert "SYN Flood" in content

    def test_get_recent_alerts_limit(self):
        for i in range(10):
            result = {
                "severity": "MEDIUM",
                "is_threat": True,
                "attack_type": f"Attack-{i}",
            }
            self.manager.process_alert(result)
        recent = self.manager.get_recent_alerts(5)
        assert len(recent) == 5

    def test_get_alert_counts_returns_copy(self):
        counts = self.manager.get_alert_counts()
        counts["CRITICAL"] = 999
        assert self.manager.alert_counts["CRITICAL"] == 0

    def test_get_stats(self):
        result = {"severity": "HIGH", "is_threat": True, "attack_type": "Test"}
        self.manager.process_alert(result)
        stats = self.manager.get_stats()
        assert stats["total_threats"] == 1
        assert stats["total_packets"] == 1

    def test_clear_history(self):
        result = {"severity": "LOW", "is_threat": True, "attack_type": "Test"}
        self.manager.process_alert(result)
        assert len(self.manager.alert_history) == 1
        self.manager.clear_history()
        assert len(self.manager.alert_history) == 0
