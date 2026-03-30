import os
import time
import threading
from datetime import datetime
from src.utils.logger import setup_logger
from src.utils.config import config

logger = setup_logger("snort_listener")

class SnortListener:

    def __init__(self):
        self.alert_log = config.get("snort", "alert_log", default="data/logs/snort_alerts.log")
        self.alert_queue = []
        self.is_running = False
        self._listener_thread = None
        self._last_position = 0

    def _parse_alert(self, line: str) -> dict:
        try:
            alert = {
                "timestamp": datetime.now().isoformat(),
                "raw": line.strip(),
                "priority": "MEDIUM",
                "message": "",
                "src_ip": "",
                "dst_ip": "",
                "protocol": ""
            }

            if "[**]" in line:
                parts = line.split("[**]")
                if len(parts) >= 2:
                    alert["message"] = parts[1].strip()

            if "[Priority:" in line:
                priority_part = line.split("[Priority:")[1]
                priority_num = int(priority_part.split("]")[0].strip())
                priority_map = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
                alert["priority"] = priority_map.get(priority_num, "MEDIUM")

            if "{" in line and "}" in line:
                protocol_part = line.split("{")[1].split("}")[0]
                alert["protocol"] = protocol_part.strip()

            if "->" in line:
                ip_part = line.split("}")[-1].strip()
                if "->" in ip_part:
                    src, dst = ip_part.split("->")
                    alert["src_ip"] = src.strip().split(":")[0]
                    alert["dst_ip"] = dst.strip().split(":")[0]

            return alert

        except Exception as e:
            logger.warning(f"Error parsing snort alert: {e}")
            return None

    def _listen_loop(self):
        logger.info(f"Listening for Snort alerts at: {self.alert_log}")
        os.makedirs(os.path.dirname(self.alert_log), exist_ok=True)

        while self.is_running:
            try:
                if not os.path.exists(self.alert_log):
                    time.sleep(2)
                    continue

                with open(self.alert_log, "r") as f:
                    f.seek(self._last_position)
                    new_lines = f.readlines()
                    self._last_position = f.tell()

                for line in new_lines:
                    line = line.strip()
                    if line and "[**]" in line:
                        alert = self._parse_alert(line)
                        if alert:
                            self.alert_queue.append(alert)
                            logger.warning(f"Snort alert: {alert['message']}")

                time.sleep(1)

            except Exception as e:
                logger.error(f"Snort listener error: {e}")
                time.sleep(2)

    def start(self):
        if self.is_running:
            logger.warning("Snort listener already running")
            return
        self.is_running = True
        self._listener_thread = threading.Thread(
            target=self._listen_loop,
            daemon=True
        )
        self._listener_thread.start()
        logger.info("Snort listener started")

    def stop(self):
        self.is_running = False
        logger.info("Snort listener stopped")

    def get_alerts(self) -> list:
        alerts = self.alert_queue.copy()
        self.alert_queue.clear()
        return alerts

    def get_alert_count(self) -> int:
        return len(self.alert_queue)
