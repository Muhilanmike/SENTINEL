import os
from flask import Flask
from flask_socketio import SocketIO
from src.utils.logger import setup_logger
from src.utils.config import config

logger = setup_logger("dashboard")

template_dir = os.path.join(os.path.dirname(__file__), "templates")
app = Flask(__name__, template_folder=template_dir)
app.config["SECRET_KEY"] = "sentinel-ids-secret-key"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

def create_app():
    from src.dashboard.routes import register_routes
    register_routes(app, socketio)
    return app, socketio

def run_dashboard(alert_manager, decision_engine):
    app_instance, socketio_instance = create_app()
    host = config.get("dashboard", "host", default="0.0.0.0")
    port = config.get("dashboard", "port", default=5000)
    debug = config.get("dashboard", "debug", default=False)
    logger.info(f"Starting dashboard at http://{host}:{port}")
    socketio_instance.run(app_instance, host=host, port=port, debug=debug)
