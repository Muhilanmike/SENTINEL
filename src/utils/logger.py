import logging
import os
from logging.handlers import RotatingFileHandler
import colorlog

def setup_logger(name: str, log_file: str = "data/logs/sentinel.log", level: str = "INFO") -> logging.Logger:

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if logger.handlers:
        return logger

    # Console handler with colors
    console_handler = colorlog.StreamHandler()
    console_handler.setFormatter(colorlog.ColoredFormatter(
        "%(log_color)s[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        log_colors={
            "DEBUG":    "cyan",
            "INFO":     "green",
            "WARNING":  "yellow",
            "ERROR":    "red",
            "CRITICAL": "bold_red",
        }
    ))

    # File handler with rotation
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=50 * 1024 * 1024,
        backupCount=5
    )
    file_handler.setFormatter(logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger
