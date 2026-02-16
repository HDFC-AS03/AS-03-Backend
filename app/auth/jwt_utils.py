# app/auth/jwt_utils.py
from typing import Dict, Any, Optional
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


async def validate_bearer_token(
    token: str,
    audience: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Validate RS256 JWT using Keycloak JWKS.
    Supports optional audience validation.
    """
    try:
        jwks = await _fetch_jwks()

        options = {
            "verify_aud": bool(audience),
            "verify_exp": True,
            "verify_iss": True,
        }

        claims = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            audience=audience,
            issuer=f"{settings.KEYCLOAK_SERVER_URL}/realms/{settings.KEYCLOAK_REALM}",
            options=options,
        )

        return claims

    except JWTError as e:
        logger.warning(f"JWT validation error: {e}")
        raise ValueError("Invalid token") from e

    except Exception as e:
        logger.exception("Unexpected token validation error")
        raise ValueError("Token validation failed") from e
