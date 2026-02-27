from typing import Dict, Any
import time
import logging
import httpx
from jose import jwt, JWTError
from cachetools import TTLCache
from .config import settings

logger = logging.getLogger("jwt_utils")

# Cache JWKS for 10 minutes
_jwks_cache = TTLCache(maxsize=2, ttl=600)

async def _fetch_jwks() -> Dict[str, Any]:
    key = "jwks"
    if key in _jwks_cache:
        return _jwks_cache[key]

    url = f"{settings.KEYCLOAK_SERVER_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/certs"
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url)
        r.raise_for_status()
        jwks = r.json()
        _jwks_cache[key] = jwks
        return jwks

async def validate_bearer_token(token: str, audience: str = None) -> Dict[str, Any]:
    """Validate an RS256 JWT using Keycloak JWKS. Returns claims on success.

    Raises HTTPException-like errors (ValueError) on failure.
    """
    try:
        jwks = await _fetch_jwks()
        # jose will select the correct key from jwks
        options = {
            "verify_aud": bool(audience),
            "exp": True,
            "iss": True,
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
        logger.exception("Unexpected error validating token")
        raise ValueError("Token validation failed") from e
