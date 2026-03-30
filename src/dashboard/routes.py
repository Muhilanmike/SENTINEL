from flask import render_template, jsonify
from flask_socketio import emit
from src.utils.logger import setup_logger
import threading
import time

logger = setup_logger("routes")

_alert_manager = None
_decision_engine = None

def register_routes(app, socketio):

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/stats")
    def get_stats():
        if _alert_manager:
            return jsonify(build_stats(_alert_manager))
        return jsonify({"status": "initializing"})

    @socketio.on("connect")
    def handle_connect():
        logger.info("Dashboard client connected")
        if _alert_manager:
            stats = build_stats(_alert_manager)
            alerts = _alert_manager.get_recent_alerts(50)
            emit("init_data", {"stats": stats, "alerts": alerts})
        else:
            emit("connected", {"status": "connected"})

    @socketio.on("disconnect")
    def handle_disconnect():
        logger.info("Dashboard client disconnected")

def build_stats(alert_manager):
    """Build stats dict from an AlertManager instance. Shared by routes and main."""
    if not alert_manager:
        return {}
    counts = alert_manager.get_alert_counts()
    alerts = alert_manager.get_recent_alerts(200)
    total = sum(counts.values())
    malicious = total - counts.get("NORMAL", 0)
    category_counts = {}
    protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0}
    top_ips = {}
    severity_counts = {
        "critical": counts.get("CRITICAL", 0),
        "high": counts.get("HIGH", 0),
        "medium": counts.get("MEDIUM", 0),
        "low": counts.get("LOW", 0),
    }
    for alert in alerts:
        cat = alert.get("attack_type", "Unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1
        proto = alert.get("protocol", "TCP")
        if proto in protocol_counts:
            protocol_counts[proto] += 1
        src_ip = alert.get("src_ip", "")
        if src_ip:
            top_ips[src_ip] = top_ips.get(src_ip, 0) + 1
    top_ips = dict(sorted(
        top_ips.items(), key=lambda x: x[1], reverse=True
    )[:8])
    fp_reduction = round((counts.get("LOW", 0) / max(malicious, 1)) * 100)
    return {
        "total": total,
        "malicious": malicious,
        "critical": counts.get("CRITICAL", 0),
        "suspicious": counts.get("HIGH", 0) + counts.get("MEDIUM", 0),
        "fp_reduction": fp_reduction,
        "fp_suppressions": counts.get("LOW", 0),
        "rules_generated": 0,
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "protocol_counts": protocol_counts,
        "top_ips": top_ips,
        "traffic_labels": [],
        "traffic_normal": [],
        "traffic_suspicious": [],
        "heatmap_data": [[0]*24 for _ in range(7)],
    }

def start_stats_broadcaster(socketio, alert_manager, decision_engine):
    global _alert_manager, _decision_engine
    _alert_manager = alert_manager
    _decision_engine = decision_engine

    def broadcast_loop():
        while True:
            try:
                stats = build_stats(_alert_manager)
                socketio.emit("stats_update", stats)
                time.sleep(3)
            except Exception as e:
                logger.error(f"Broadcast error: {e}")
                time.sleep(3)

    t = threading.Thread(target=broadcast_loop, daemon=True)
    t.start()
    logger.info("Stats broadcaster started")
