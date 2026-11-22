"""
Logging Configuration for RecoverX
Provides structured, timestamped console and file logging.
"""
import logging
import sys
from pathlib import Path
from config import REPORTS_DIR

_logger_initialized = False

def setup_logger(name: str = "recoverx", level: int = logging.INFO, log_to_file: bool = True) -> logging.Logger:
    global _logger_initialized
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        # Console Formatter
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_fmt = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        console_handler.setFormatter(console_fmt)
        logger.addHandler(console_handler)

        if log_to_file:
            log_file = REPORTS_DIR / "recoverx.log"
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_fmt = logging.Formatter(
                "%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d]: %(message)s"
            )
            file_handler.setFormatter(file_fmt)
            logger.addHandler(file_handler)

    return logger

logger = setup_logger()

