import json
import os
import threading
from datetime import datetime
from src.utils.logger import setup_logger
from src.utils.config import config

logger = setup_logger("alert_manager")

class AlertManager:

    def __init__(self):
        self.alert_log = config.get("alerts", "log_path", default="data/logs/alerts.log")
        self.alert_history = []
        self.alert_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "NORMAL": 0
        }
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.alert_log), exist_ok=True)

    def process_alert(self, analysis_result: dict):
        try:
            severity = analysis_result.get("severity", "NORMAL")
            is_threat = analysis_result.get("is_threat", False)

            with self._lock:
                if not is_threat:
                    self.alert_counts["NORMAL"] += 1
                    return

                alert = {
                    "id": len(self.alert_history) + 1,
                    "timestamp": datetime.now().isoformat(),
                    "severity": severity,
                    "attack_type": analysis_result.get("attack_type", "Unknown"),
                    "src_ip": analysis_result.get("src_ip", ""),
                    "dst_ip": analysis_result.get("dst_ip", ""),
                    "src_port": analysis_result.get("src_port", 0),
                    "dst_port": analysis_result.get("dst_port", 0),
                    "protocol": analysis_result.get("protocol", ""),
                    "rf_label": analysis_result.get("rf_label", ""),
                    "rf_confidence": analysis_result.get("rf_confidence", 0.0),
                    "if_anomaly_score": analysis_result.get("if_anomaly_score", 0.0),
                }

                self.alert_history.append(alert)
                self.alert_counts[severity] = self.alert_counts.get(severity, 0) + 1

            self._save_alert(alert)
            self._log_alert(alert)

        except Exception as e:
            logger.error(f"Alert processing error: {e}")

    def _log_alert(self, alert: dict):
        severity = alert["severity"]
        msg = (f"[{severity}] {alert['attack_type']} | "
               f"{alert['src_ip']}:{alert['src_port']} -> "
               f"{alert['dst_ip']}:{alert['dst_port']}")

        if severity == "CRITICAL":
            logger.critical(msg)
        elif severity == "HIGH":
            logger.error(msg)
        elif severity == "MEDIUM":
            logger.warning(msg)
        else:
            logger.info(msg)

    def _save_alert(self, alert: dict):
        try:
            with open(self.alert_log, "a") as f:
                f.write(json.dumps(alert) + "\n")
        except Exception as e:
            logger.error(f"Error saving alert: {e}")

    def get_recent_alerts(self, limit: int = 50) -> list:
        with self._lock:
            return self.alert_history[-limit:]

    def get_alert_counts(self) -> dict:
        with self._lock:
            return self.alert_counts.copy()

    def get_stats(self) -> dict:
        total = sum(self.alert_counts.values())
        threats = total - self.alert_counts.get("NORMAL", 0)
        return {
            "total_packets": total,
            "total_threats": threats,
            "counts": self.alert_counts,
            "recent_alerts": self.get_recent_alerts(10)
        }

    def clear_history(self):
        self.alert_history.clear()
        logger.info("Alert history cleared")
