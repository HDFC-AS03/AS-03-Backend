from typing import Dict, Any
import logging
import httpx
from jose import jwt, JWTError
from cachetools import TTLCache
from app.core.config import settings

logger = logging.getLogger("jwt")

_jwks_cache = TTLCache(maxsize=2, ttl=600)


async def _fetch_jwks() -> Dict[str, Any]:
    if "jwks" in _jwks_cache:
        return _jwks_cache["jwks"]

    url = (
        f"{settings.KEYCLOAK_SERVER_URL}/realms/"
        f"{settings.KEYCLOAK_REALM}/protocol/openid-connect/certs"
    )

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url)
        r.raise_for_status()
        jwks = r.json()
        _jwks_cache["jwks"] = jwks
        return jwks


async def validate_bearer_token(token: str) -> Dict[str, Any]:
    try:
        jwks = await _fetch_jwks()

        claims = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            issuer=f"{settings.KEYCLOAK_SERVER_URL}/realms/{settings.KEYCLOAK_REALM}",
            options={"verify_aud": False},
        )
        return claims

    except JWTError as e:
        logger.warning(f"JWT validation error: {e}")
        raise ValueError("Invalid token")
