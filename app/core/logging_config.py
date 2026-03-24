import logging
import sys
import json
from datetime import datetime
import os


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": "auth-service",
        }

        # SAFE extra handling
        for key, value in record.__dict__.items():
            if key not in (
                "name", "msg", "args", "levelname", "levelno",
                "pathname", "filename", "module", "exc_info",
                "exc_text", "stack_info", "lineno", "funcName",
                "created", "msecs", "relativeCreated", "thread",
                "threadName", "processName", "process"
            ):
                try:
                    json.dumps(value)
                    log_record[key] = value
                except:
                    log_record[key] = str(value)

        return json.dumps(log_record)


def setup_logging():
    formatter = JsonFormatter()

    # Ensure logs directory exists
    os.makedirs("/app/logs", exist_ok=True)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    # File handler (IMPORTANT)
    file_handler = logging.FileHandler("/app/logs/audit.log")
    file_handler.setFormatter(formatter)

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # 🔥 IMPORTANT: attach BOTH handlers
    root_logger.handlers = [console_handler, file_handler]

    # Audit logger
    audit_logger = logging.getLogger("audit")
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = True