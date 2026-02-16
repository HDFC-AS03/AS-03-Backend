from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional


def wrap_response(
    data: Any,
    message: str = "Success",
    success: bool = True,
    ttl: Optional[int] = None,
    version: str = "1.0"
) -> Dict[str, Any]:

    now = datetime.now(timezone.utc)

    response = {
        "success": success,
        "message": message,
        "data": data,
        "metadata": {
            "timestamp": now.isoformat().replace("+00:00", "Z"),
            "version": version,
        }
    }

    if ttl is not None:
        expires_at = now + timedelta(seconds=ttl)
        response["metadata"]["ttl"] = {
            "value": ttl,
            "unit": "seconds",
            "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        }

    return response
