import time
import logging
from starlette.middleware.base import BaseHTTPMiddleware


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        start = time.time()

        response = await call_next(request)

        duration = round(time.time() - start, 3)

        logging.getLogger("audit").info(
            "API request",
            extra={
                "method": request.method,
                "endpoint": request.url.path,
                "status_code": response.status_code,
                "ip": request.client.host,
                "duration": duration,
            },
        )

        return response