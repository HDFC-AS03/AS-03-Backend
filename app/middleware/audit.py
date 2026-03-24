import time
import logging
from starlette.middleware.base import BaseHTTPMiddleware


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        logger = logging.getLogger("audit")
        start = time.time()

        try:
            response = await call_next(request)
            latency_ms = int((time.time() - start) * 1000)

            # Try to get user_id if set by auth middleware
            user_id = getattr(request.state, "user_id", None)

            logger.info(
                "API request",
                extra={
                    "event": "api_request",
                    "method": request.method,
                    "endpoint": request.url.path,
                    "status_code": response.status_code,
                    "ip": request.client.host if request.client else None,
                    "latency_ms": latency_ms,
                    "user_id": user_id,
                    "success": response.status_code < 400,
                },
            )

            return response

        except Exception as e:
            latency_ms = int((time.time() - start) * 1000)

            logger.error(
                "Unhandled exception",
                extra={
                    "event": "error",
                    "method": request.method,
                    "endpoint": request.url.path,
                    "status_code": 500,
                    "ip": request.client.host if request.client else None,
                    "latency_ms": latency_ms,
                    "error": str(e),
                    "success": False,
                },
            )

            raise