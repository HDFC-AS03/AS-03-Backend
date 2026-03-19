# Backend Code Explanation

Complete guide to understanding how the Keycloak OAuth2 authentication backend works, including the API Gateway with RS256 JWT validation.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Authentication Flow](#authentication-flow)
3. [File Structure](#file-structure)
4. [Core Components](#core-components)
   - [Configuration (config.py)](#1-configuration-configpy)
   - [OAuth Setup (oauth.py)](#2-oauth-setup-oauthpy)
   - [Routes (routes.py)](#3-routes-routespy)
   - [JWT Utilities (jwt_utils.py)](#4-jwt-utilities-jwt_utilspy)
   - [Auth Dependencies (dependencies.py)](#5-auth-dependencies-dependenciespy)
   - [Response Wrapper (response_wrapper.py)](#6-response-wrapper-response_wrapperpy)
5. [API Gateway](#api-gateway)
   - [NGINX Configuration](#nginx-configuration)
   - [JWT Validator (Lua)](#jwt-validator-lua)
6. [Security Features](#security-features)
7. [Development vs Production](#development-vs-production)

---

## Architecture Overview

```
┌────────────────┐     ┌─────────────────┐     ┌────────────────┐     ┌──────────────┐
│                │     │                 │     │                │     │              │
│    Frontend    │◄───►│   API Gateway   │◄───►│    Backend     │◄───►│   Keycloak   │
│  (React/Vite)  │     │   (OpenResty)   │     │   (FastAPI)    │     │    (IdP)     │
│                │     │                 │     │                │     │              │
└────────────────┘     └─────────────────┘     └────────────────┘     └──────────────┘
     :5173                   :80                    :8000                  :8080
```

**Request Flow:**
1. Frontend makes request to Gateway (port 80)
2. Gateway validates JWT signature using RS256 + Keycloak JWKS
3. Valid requests proxied to Backend (port 8000)
4. Backend handles business logic
5. Backend talks to Keycloak for token operations

---

## Authentication Flow

### Login Flow
```
┌──────────┐    ┌─────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ Frontend │───►│ Gateway │───►│ Backend  │───►│ Keycloak │───►│ Keycloak │
│          │    │         │    │ /login   │    │ /auth    │    │ Login UI │
└──────────┘    └─────────┘    └──────────┘    └──────────┘    └──────────┘
                                                                     │
┌──────────┐    ┌─────────┐    ┌──────────┐    ◄──────────────────────┘
│ Frontend │◄───│ Gateway │◄───│ Backend  │    User authenticates
│ /dashboard    │         │    │ /callback│    
│ + tokens │    │         │    │          │    
└──────────┘    └─────────┘    └──────────┘    
```

### Token Refresh Flow
```
┌──────────┐    ┌─────────┐    ┌──────────┐    ┌──────────┐
│ Frontend │───►│ Gateway │───►│ Backend  │───►│ Keycloak │
│ POST     │    │ (bypass)│    │ /refresh │    │ /token   │
│ /refresh │    │         │    │          │    │          │
└──────────┘    └─────────┘    └──────────┘    └──────────┘
     │                              │
     │◄─────────────────────────────┘
     │   new access_token + rotated refresh_token
```

---

## File Structure

```
AS-03-Backend/
├── app/
│   ├── __init__.py           # Package marker
│   ├── main.py               # FastAPI application entry point
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py         # All API endpoints
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── dependencies.py   # FastAPI dependencies (require_auth, require_role)
│   │   ├── jwt_utils.py      # JWT validation utilities
│   │   └── oauth.py          # Authlib OAuth client setup
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py         # Pydantic settings (env vars)
│   │   ├── logging_config.py # Logging setup
│   │   └── response_wrapper.py # Standardized API responses
│   └── services/
│       └── admin_services.py # Admin API services (optional)
├── gateway/
│   ├── nginx.conf            # OpenResty NGINX configuration
│   └── lua/
│       └── jwt_validator.lua # RS256 JWT validation in Lua
└── docker-compose/
    └── docker-compose.yml    # All services orchestration
```

---

## Core Components

### 1. Configuration (config.py)

**Purpose:** Centralized configuration using Pydantic settings with environment variable support.

```python
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")
    
    # Environment mode
    ENV: str = "dev"
    
    # Keycloak connection
    KEYCLOAK_CLIENT_ID: str             # OAuth client ID
    KEYCLOAK_CLIENT_SECRET: str         # OAuth client secret
    KEYCLOAK_REALM: str                 # Keycloak realm name
    KEYCLOAK_SERVER_URL: str = "http://localhost:8080"
    
    # Frontend URL for redirects
    FRONTEND_URL: str = "http://localhost:5173"
```

**How it works:**
- Pydantic automatically reads environment variables
- `env_file=".env"` allows loading from `.env` file
- All config accessed via `settings.VARIABLE_NAME`

---

### 2. OAuth Setup (oauth.py)

**Purpose:** Configure Authlib OAuth client for Keycloak integration.

```python
from authlib.integrations.starlette_client import OAuth
from app.core.config import settings

oauth = OAuth()

# Two different URLs:
# - KEYCLOAK_EXTERNAL_URL: Browser-facing (localhost:8080)
# - KEYCLOAK_SERVER_URL: Backend-to-Keycloak (keycloak:8080 in Docker)

oauth.register(
    name="keycloak",
    client_id=settings.KEYCLOAK_CLIENT_ID,
    client_secret=settings.KEYCLOAK_CLIENT_SECRET,
    
    # Browser goes here (must be accessible from user's browser)
    authorize_url=f"{KEYCLOAK_EXTERNAL_URL}/realms/{realm}/protocol/openid-connect/auth",
    
    # Backend fetches tokens here (Docker internal network)
    access_token_url=f"{settings.KEYCLOAK_SERVER_URL}/realms/{realm}/protocol/openid-connect/token",
    
    # JWKS for token validation
    jwks_uri=f"{settings.KEYCLOAK_SERVER_URL}/realms/{realm}/protocol/openid-connect/certs",
    
    client_kwargs={"scope": "openid email profile"},
)
```

**Key Concept - Two URLs:**
| URL | Used By | Purpose |
|-----|---------|---------|
| `localhost:8080` | Browser | User sees this in address bar |
| `keycloak:8080` | Backend container | Docker internal DNS resolution |

---

### 3. Routes (routes.py)

**Purpose:** All API endpoints including OAuth flow and protected routes.

#### Configuration Constants

```python
# Cookie settings
COOKIE_NAME = "refresh_token"      # httpOnly cookie name
CSRF_COOKIE_NAME = "csrf_token"    # Double-submit CSRF token
COOKIE_MAX_AGE = 60 * 60 * 24 * 7  # 7 days

# Environment detection
IS_PRODUCTION = os.getenv("ENV", "dev") == "production"
USE_COOKIE_REFRESH = IS_PRODUCTION  # httpOnly cookies only in prod
```

#### CSRF Protection

```python
def generate_csrf_token() -> str:
    """Cryptographically secure random token (43 chars)."""
    return secrets.token_urlsafe(32)

async def validate_csrf(
    request: Request,
    x_csrf_token: str | None = Header(None, alias="X-CSRF-Token"),
):
    """
    Double-submit cookie pattern:
    1. Cookie 'csrf_token' set on login (readable by JS)
    2. Frontend reads cookie, sends as X-CSRF-Token header
    3. Backend compares cookie value == header value
    4. Attacker can't read cookie from different origin (SameSite=lax)
    """
    if not USE_COOKIE_REFRESH:
        return True  # Skip in dev (no cookies)
    
    csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
    
    # Timing-safe comparison prevents timing attacks
    if not secrets.compare_digest(csrf_cookie, x_csrf_token):
        raise HTTPException(status_code=403, detail="CSRF token mismatch")
    
    return True
```

#### Login Endpoint

```python
@router.get("/login")
async def login(request: Request):
    # Generate callback URL based on current request
    redirect_uri = request.url_for("auth_callback")
    
    # Redirect to Keycloak login page
    return await oauth.keycloak.authorize_redirect(request, redirect_uri)
```

**Flow:**
1. User clicks "Login" → Frontend redirects to `/login`
2. Backend redirects to Keycloak login page
3. Keycloak shows login form
4. After login, Keycloak redirects back to `/callback`

#### Callback Endpoint

```python
@router.get("/callback", name="auth_callback")
async def auth_callback(request: Request):
    # Exchange authorization code for tokens
    token = await oauth.keycloak.authorize_access_token(request)
    
    access_token = token["access_token"]
    refresh_token = token.get("refresh_token")
    
    if USE_COOKIE_REFRESH:  # Production
        # Only access_token in URL (frontend stores in memory)
        token_params = urlencode({"access_token": access_token})
        response = RedirectResponse(url=f"{settings.FRONTEND_URL}/dashboard#{token_params}")
        
        # Refresh token in httpOnly cookie (XSS-proof)
        response.set_cookie(
            key=COOKIE_NAME,
            value=refresh_token,
            httponly=True,   # JavaScript cannot read this
            secure=True,     # HTTPS only
            samesite="lax",  # CSRF protection
            max_age=COOKIE_MAX_AGE,
        )
        
        # CSRF token cookie (readable by JS for double-submit)
        csrf_token = generate_csrf_token()
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=csrf_token,
            httponly=False,  # Must be readable by JavaScript
            secure=True,
            samesite="lax",
        )
    else:  # Development
        # Both tokens in URL hash (frontend stores in sessionStorage)
        token_params = urlencode({
            "access_token": access_token,
            "refresh_token": refresh_token,
        })
        response = RedirectResponse(url=f"{settings.FRONTEND_URL}/dashboard#{token_params}")
    
    return response
```

**Why URL Hash (#)?**
- Hash fragments are NOT sent to server
- Only frontend JavaScript can read them
- Prevents access_token from appearing in server logs
- Safer than query parameters (?token=xxx)

#### Refresh Endpoint

```python
@router.post("/refresh")
async def refresh_token(
    request: Request,
    response: Response,
    _csrf: bool = Depends(validate_csrf),  # CSRF required in prod
):
    # Get refresh token based on mode
    if USE_COOKIE_REFRESH:
        refresh_token_value = request.cookies.get(COOKIE_NAME)
    else:
        body = await request.json()
        refresh_token_value = body.get("refresh_token")
    
    # Call Keycloak token endpoint
    async with httpx.AsyncClient(timeout=10) as client:
        keycloak_response = await client.post(
            token_url,
            data={
                "grant_type": "refresh_token",
                "client_id": settings.KEYCLOAK_CLIENT_ID,
                "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
                "refresh_token": refresh_token_value,
            },
        )
    
    new_tokens = keycloak_response.json()
    
    # Rotate tokens (Keycloak returns new refresh_token)
    if USE_COOKIE_REFRESH:
        # Update httpOnly cookie with new refresh token
        response.set_cookie(key=COOKIE_NAME, value=new_tokens["refresh_token"], ...)
        
        # Rotate CSRF token too
        new_csrf = generate_csrf_token()
        response.set_cookie(key=CSRF_COOKIE_NAME, value=new_csrf, ...)
        
        return {"access_token": new_tokens["access_token"], "csrf_token": new_csrf}
    else:
        return {
            "access_token": new_tokens["access_token"],
            "refresh_token": new_tokens["refresh_token"],
        }
```

#### Protected Endpoints

```python
@router.get("/me")
async def get_current_user(user: dict = Depends(require_auth)):
    """Returns current user info. Requires valid JWT."""
    return wrap_response(user_data)

@router.get("/admin")
async def admin_only(user: dict = Depends(require_role("admin"))):
    """Only users with 'admin' role can access."""
    return {"message": "Admin access granted"}
```

---

### 4. JWT Utilities (jwt_utils.py)

**Purpose:** Validate JWT tokens using Keycloak's JWKS (JSON Web Key Set).

```python
from jose import jwt, JWTError
from cachetools import TTLCache

# Cache JWKS for 10 minutes (avoid fetching on every request)
_jwks_cache = TTLCache(maxsize=2, ttl=600)

async def _fetch_jwks() -> Dict[str, Any]:
    """Fetch Keycloak's public keys for RS256 verification."""
    if "jwks" in _jwks_cache:
        return _jwks_cache["jwks"]
    
    # Fetch from Keycloak
    url = f"{settings.KEYCLOAK_SERVER_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/certs"
    
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url)
        jwks = r.json()
        _jwks_cache["jwks"] = jwks
        return jwks

async def validate_bearer_token(token: str) -> Dict[str, Any]:
    """
    Validate JWT:
    1. Fetch JWKS (cached)
    2. Verify RS256 signature
    3. Check expiry (exp claim)
    4. Validate issuer (accept both internal and external URLs)
    """
    jwks = await _fetch_jwks()
    
    # Decode and verify signature
    claims = jwt.decode(
        token,
        jwks,
        algorithms=["RS256"],  # Only accept RS256
        options={"verify_iss": False},  # Manual issuer check below
    )
    
    # Accept tokens from both Docker internal and localhost
    valid_issuers = [
        f"{settings.KEYCLOAK_SERVER_URL}/realms/{settings.KEYCLOAK_REALM}",
        f"http://localhost:8080/realms/{settings.KEYCLOAK_REALM}",
    ]
    if claims["iss"] not in valid_issuers:
        raise ValueError("Invalid token issuer")
    
    return claims
```

**Why RS256?**
- Asymmetric encryption (public/private key pair)
- Keycloak signs with private key
- Anyone can verify with public key (JWKS)
- No shared secret needed

---

### 5. Auth Dependencies (dependencies.py)

**Purpose:** FastAPI dependencies for protecting routes.

```python
async def get_bearer_user(request: Request):
    """Extract and validate JWT from Authorization header."""
    auth = request.headers.get("Authorization")
    
    if not auth or not auth.startswith("Bearer "):
        return None
    
    token = auth.split(" ", 1)[1]
    
    try:
        claims = await validate_bearer_token(token)
        return {
            "sub": claims["sub"],           # User ID
            "email": claims["email"],
            "preferred_username": claims["preferred_username"],
            "roles": claims.get("realm_access", {}).get("roles", []),
            "claims": claims,               # Full JWT claims
        }
    except ValueError:
        return None

async def require_auth(user: dict = Depends(get_bearer_user)):
    """Require valid JWT bearer token."""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

def require_role(role: str):
    """Factory function that creates a role-checking dependency."""
    def checker(user: dict = Depends(require_auth)):
        # Check realm roles
        realm_roles = user.get("roles", [])
        
        # Check client roles (resource_access)
        client_roles = []
        claims = user.get("claims", {})
        for client_data in claims.get("resource_access", {}).values():
            client_roles.extend(client_data.get("roles", []))
        
        all_roles = set(realm_roles + client_roles)
        
        if role not in all_roles:
            raise HTTPException(status_code=403, detail=f"'{role}' role required")
        
        return user
    
    return checker
```

**Usage:**
```python
@router.get("/me")
async def get_me(user = Depends(require_auth)):  # Any authenticated user
    ...

@router.get("/admin")
async def admin(user = Depends(require_role("admin"))):  # Only admins
    ...
```

---

### 6. Response Wrapper (response_wrapper.py)

**Purpose:** Standardized API response format with metadata.

```python
def wrap_response(
    data: Any,
    message: str = "Success",
    success: bool = True,
    ttl: Optional[int] = None,  # Cache TTL in seconds
    version: str = "1.0"
) -> Dict[str, Any]:
    
    return {
        "success": True,
        "message": "User information retrieved successfully",
        "data": { ... },
        "metadata": {
            "timestamp": "2026-03-04T12:00:00Z",
            "version": "1.0",
            "ttl": {
                "value": 300,
                "unit": "seconds",
                "expires_at": "2026-03-04T12:05:00Z"
            }
        }
    }
```

---

## API Gateway

### NGINX Configuration

**Location:** `shared-infra/gateway/nginx.conf`

```nginx
events {}

http {
    lua_package_path "/usr/local/openresty/nginx/lua/?.lua;;";
    
    # Docker DNS resolver
    resolver 127.0.0.11 valid=30s;
    
    # Shared memory for JWKS cache (1MB)
    lua_shared_dict jwks_cache 1m;

    upstream backend_service {
        server backend:8000;  # Docker service name
    }

    server {
        listen 80;
        
        # CORS configuration
        set $cors_origin "";
        if ($http_origin ~* "^http://localhost:(5173|3000|8080)$") {
            set $cors_origin $http_origin;
        }

        # Auth endpoints - bypass JWT validation
        location ~ ^/(login|logout|callback|refresh)$ {
            # CORS preflight
            if ($request_method = 'OPTIONS') {
                add_header 'Access-Control-Allow-Origin' $cors_origin;
                add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS';
                add_header 'Access-Control-Allow-Headers' 'Authorization, Content-Type';
                add_header 'Access-Control-Allow-Credentials' 'true';
                return 204;
            }
            
            proxy_pass http://backend_service;
            proxy_pass_header Set-Cookie;  # Pass cookies through
        }

        # Protected endpoints - JWT validation required
        location / {
            # CORS preflight
            if ($request_method = 'OPTIONS') {
                add_header 'Access-Control-Allow-Origin' $cors_origin;
                return 204;
            }

            # ⚡ JWT validation happens here (Lua script)
            access_by_lua_file /usr/local/openresty/nginx/lua/jwt_validator.lua;

            proxy_pass http://backend_service;
        }
    }
}
```

**Key Points:**
- Auth endpoints bypass JWT (needed for login flow)
- All other endpoints require valid JWT
- CORS headers added by gateway (not backend)
- `access_by_lua_file` runs JWT validation before proxying

---

### JWT Validator (Lua)

**Location:** `shared-infra/gateway/lua/jwt_validator.lua`

This is the **security core** - RS256 signature verification using OpenSSL FFI.

#### Configuration

```lua
local JWKS_URL = "http://keycloak:8080/realms/auth-realm/protocol/openid-connect/certs"

-- Accept both internal and external issuers
local EXPECTED_ISSUERS = {
    ["http://keycloak:8080/realms/auth-realm"] = true,
    ["http://localhost:8080/realms/auth-realm"] = true,
}

local JWKS_CACHE_TTL = 300  -- 5 minutes
```

#### Main Validation Flow

```lua
-- 1. Get Authorization header
local auth_header = ngx.var.http_authorization
if not auth_header then
    return send_error(401, "Missing Authorization header")
end

-- 2. Extract Bearer token
local token = string.match(auth_header, "Bearer%s+(.+)")

-- 3. Split into header.payload.signature
local parts = {} -- Split by "."
local header_b64, payload_b64, signature_b64 = parts[1], parts[2], parts[3]

-- 4. Parse JWT header
local header = cjson.decode(base64url_decode(header_b64))

-- 5. SECURITY: Only allow RS256 (prevents algorithm confusion attack)
if header.alg ~= "RS256" then
    return send_error(401, "Unsupported algorithm")
end

-- 6. Fetch JWKS from Keycloak (cached)
local jwks = fetch_jwks()

-- 7. Find key by 'kid' (key ID)
local jwk = find_key_by_kid(jwks, header.kid)

-- 8. Handle key rotation: if not found, refresh JWKS
if not jwk then
    jwks = fetch_jwks(true)  -- force refresh
    jwk = find_key_by_kid(jwks, header.kid)
end

-- 9. Convert JWK to PEM format
local pem_key = jwk_to_pem(jwk)

-- 10. ⚡ VERIFY RS256 SIGNATURE (Critical security step)
local verified = verify_rs256(header_b64, payload_b64, signature_b64, pem_key)
if not verified then
    return send_error(401, "Invalid token signature")
end

-- 11. Validate expiry
if payload.exp < ngx.time() then
    return send_error(401, "Token expired")
end

-- 12. Validate issuer
if not EXPECTED_ISSUERS[payload.iss] then
    return send_error(401, "Invalid issuer")
end

-- 13. Forward user claims to backend via headers
ngx.req.set_header("X-User-ID", payload.sub)
ngx.req.set_header("X-User-Email", payload.email)
ngx.req.set_header("X-Token-Verified", "true")

-- Success - request continues to backend
```

#### RS256 Verification (OpenSSL FFI)

```lua
local function verify_rs256(header_b64, payload_b64, signature_b64, pem_key)
    local signing_input = header_b64 .. "." .. payload_b64
    local signature = base64url_decode(signature_b64)
    
    -- Load public key from PEM
    local bio = crypto.BIO_new_mem_buf(pem_key, #pem_key)
    local pkey = crypto.PEM_read_bio_PUBKEY(bio, nil, nil, nil)
    
    -- Create SHA256 digest context
    local md_ctx = crypto.EVP_MD_CTX_new()
    crypto.EVP_DigestVerifyInit(md_ctx, nil, crypto.EVP_sha256(), nil, pkey)
    
    -- Hash the signing input
    crypto.EVP_DigestVerifyUpdate(md_ctx, signing_input, #signing_input)
    
    -- Verify signature matches
    local ret = crypto.EVP_DigestVerifyFinal(md_ctx, signature, #signature)
    
    return ret == 1  -- 1 = valid, 0 = invalid
end
```

---

## Security Features

### 1. RS256 Signature Verification
- Tokens signed by Keycloak's private key
- Gateway verifies using public key (JWKS)
- Prevents token forgery/tampering

### 2. httpOnly Cookies (Production)
- Refresh token stored in `httponly` cookie
- JavaScript cannot access (XSS-proof)
- `secure=true` requires HTTPS
- `samesite=lax` prevents CSRF on navigation

### 3. CSRF Protection (Double-Submit Cookie)
- `csrf_token` cookie (readable by JS)
- Frontend sends as `X-CSRF-Token` header
- Backend compares cookie == header
- Attacker can't read cookie cross-origin

### 4. Token Rotation
- Each refresh returns NEW refresh token
- Old refresh token invalidated
- Limits damage from token theft

### 5. Short-Lived Access Tokens
- Access tokens expire in minutes (configured in Keycloak)
- Refresh token used to get new access tokens
- Reduces window for stolen token usage

---

## Development vs Production

| Feature | Development | Production |
|---------|-------------|------------|
| Access Token | Memory (JS variable) | Memory (JS variable) |
| Refresh Token | sessionStorage | httpOnly cookie |
| CSRF Protection | Disabled | Enabled |
| Cookie `secure` | false | true (HTTPS required) |
| Token Delivery | Both in URL hash | Access in URL, refresh in cookie |

**Environment Variable:**
```bash
ENV=dev      # Development mode
ENV=production  # Production mode
```

**Code Check:**
```python
IS_PRODUCTION = os.getenv("ENV", "dev") == "production"
USE_COOKIE_REFRESH = IS_PRODUCTION
```

---

## Quick Reference

### Endpoints

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/login` | GET | None | Redirect to Keycloak |
| `/callback` | GET | None | OAuth callback (receives tokens) |
| `/logout` | GET | None | Clear cookies, redirect to Keycloak logout |
| `/refresh` | POST | CSRF (prod) | Exchange refresh token for new access token |
| `/me` | GET | Bearer JWT | Get current user info |
| `/admin` | GET | Bearer JWT + admin role | Admin-only endpoint |
| `/health` | GET | None | Health check |

### Headers

| Header | Purpose |
|--------|---------|
| `Authorization: Bearer <token>` | JWT access token |
| `X-CSRF-Token` | CSRF token (prod only) |
| `X-User-ID` | Set by gateway after validation |
| `X-Token-Verified` | Set by gateway (`true` if valid) |

### Cookies

| Cookie | httpOnly | Purpose |
|--------|----------|---------|
| `refresh_token` | Yes | Refresh token (prod only) |
| `csrf_token` | No | CSRF protection (prod only) |

