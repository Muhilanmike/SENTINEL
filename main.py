import sys
import time
import threading
from src.utils.logger import setup_logger
from src.utils.config import config
from src.capture.packet_capture import PacketCapture
from src.capture.snort_listener import SnortListener
from src.features.feature_extractor import FeatureExtractor
from src.engine.decision_engine import DecisionEngine
from src.engine.alert_manager import AlertManager
from src.dashboard.app import create_app
from src.dashboard.routes import start_stats_broadcaster, build_stats
from src.engine.rule_generator import SnortRuleGenerator

logger = setup_logger("main")

class SentinelIDS:

    def __init__(self):
        logger.info("Initializing Sentinel AI-IDS...")
        config.load()
        self.packet_capture = PacketCapture()
        self.snort_listener = SnortListener()
        self.feature_extractor = FeatureExtractor()
        self.decision_engine = DecisionEngine()
        self.alert_manager = AlertManager()
        self.is_running = False
        self.app = None
        self.socketio = None
        self.rule_generator = SnortRuleGenerator()

    def load_models(self):
        logger.info("Loading ML models...")
        rf_loaded, if_loaded = self.decision_engine.load_models()
        if not rf_loaded or not if_loaded:
            logger.warning("Models not found - please train first")
        return rf_loaded, if_loaded

    def _analysis_loop(self):
        logger.info("Starting analysis loop...")
        while self.is_running:
            try:
                packet = self.packet_capture.get_packet(timeout=1)
                if packet:
                    result = self.decision_engine.analyze(packet)
                    self.alert_manager.process_alert(result)
                    self.rule_generator.process_alert(result)
                    if result.get("is_threat") and self.socketio:
                        recent = self.alert_manager.get_recent_alerts(1)
                        if recent:
                            alert_data = recent[0]
                            alert_data["ml_severity"] = result.get("severity", "medium").lower()
                            alert_data["ml_category"] = result.get("attack_type", "Unknown")
                            alert_data["msg"] = result.get("attack_type", "Unknown Attack")
                            alert_data["rule_id"] = f"ML-{result.get('severity','?')}"
                            alert_data["is_false_positive"] = False
                            self.socketio.emit("new_alert", alert_data)
                            stats = build_stats(self.alert_manager)
                            self.socketio.emit("stats_update", stats)

                snort_alerts = self.snort_listener.get_alerts()
                for alert in snort_alerts:
                    logger.warning(f"Snort: {alert['message']} [{alert['priority']}]")

            except Exception as e:
                logger.error(f"Analysis loop error: {e}")
                time.sleep(1)

    def start(self):
        logger.info("=" * 50)
        logger.info("  SENTINEL AI-IDS STARTING...")
        logger.info("=" * 50)
        self.load_models()
        self.is_running = True
        self.packet_capture.start()
        self.snort_listener.start()
        analysis_thread = threading.Thread(
            target=self._analysis_loop,
            daemon=True
        )
        analysis_thread.start()
        self.app, self.socketio = create_app()
        start_stats_broadcaster(
            self.socketio,
            self.alert_manager,
            self.decision_engine
        )
        host = config.get("dashboard", "host", default="0.0.0.0")
        port = config.get("dashboard", "port", default=5000)
        logger.info(f"Dashboard running at http://localhost:{port}")
        logger.info("Sentinel IDS is running! Press CTRL+C to stop")
        try:
            self.socketio.run(
                self.app,
                host=host,
                port=port,
                debug=False
            )
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        logger.info("Stopping Sentinel IDS...")
        self.is_running = False
        self.packet_capture.stop()
        self.snort_listener.stop()
        logger.info("Sentinel IDS stopped")
        sys.exit(0)

if __name__ == "__main__":
    sentinel = SentinelIDS()
    sentinel.start()
