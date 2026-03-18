# API Gateway Documentation

## Overview

The API Gateway is built on **OpenResty** (NGINX + Lua) and serves as the central entry point for all client requests. It handles JWT authentication, rate limiting, CORS, and request routing to backend services. On the current PKCE branch, the gateway also forwards the browser OAuth endpoints used by the backend's Authorization Code + PKCE flow, including cookie-based login callback and token refresh traffic.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              CLIENT                                      │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         API GATEWAY (Port 80)                            │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────┐  ┌──────────────┐   │
│  │    CORS     │──│ JWT Validator │──│Rate Limiter│──│ Proxy Router │   │
│  └─────────────┘  └──────────────┘  └────────────┘  └──────────────┘   │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        BACKEND SERVICE (Port 8000)                       │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Architecture Components

### 1. OpenResty Base Image
The gateway uses `openresty/openresty:alpine-fat` with these Lua modules:
- `lua-resty-http` - HTTP client for JWKS fetching
- `lua-resty-hmac` - HMAC operations
- `lua-resty-string` - String utilities
- `lua-resty-jwt` - JWT parsing utilities
- `lua-resty-limit-traffic` - Rate limiting

### 2. Configuration Files
| File | Purpose |
|------|---------|
| `nginx.conf` | Main NGINX configuration (routing, CORS, upstream) |
| `lua/jwt_validator.lua` | JWT validation with RS256 signature verification |
| `Dockerfile` | Gateway container build instructions |

---

## Features

### JWT Authentication (RS256)

The gateway validates JWTs using **RS256 asymmetric cryptography**:

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   Client    │────────▶│   Gateway   │────────▶│  Keycloak   │
│             │  JWT    │             │  JWKS   │ (IdP)       │
└─────────────┘         └─────────────┘         └─────────────┘
```

**Validation Flow:**
1. Extract token from `Authorization: Bearer <token>` header or `access_token` cookie
2. Parse JWT header to get key ID (`kid`)
3. Fetch JWKS (JSON Web Key Set) from Keycloak (cached for 300 seconds)
4. Convert JWK to PEM format
5. Verify RS256 signature using OpenSSL FFI
6. Validate claims: `exp`, `nbf`, `iss`

**Accepted Issuers:**
```lua
EXPECTED_ISSUERS = {
    "http://keycloak:8080/realms/auth-realm",   -- Internal Docker
    "http://localhost:8080/realms/auth-realm",  -- External access
}
```

### Browser OAuth Session Flow (Authorization Code + PKCE)

The gateway does **not** generate PKCE values itself. Instead, it allows the backend to own the OAuth login flow while the gateway transparently proxies the public auth endpoints needed to establish and renew the browser session.

**Current backend behavior on `feature/pkce`:**
1. `GET /login` generates an OAuth `state`, a PKCE `code_verifier`, and an S256 `code_challenge`
2. The backend stores `oauth_state` and `pkce_verifier` in short-lived cookies
3. The browser is redirected to Keycloak with `code_challenge` and `code_challenge_method=S256`
4. `GET /callback` validates the `state` cookie and exchanges the authorization code using the stored `code_verifier`
5. The backend sets `access_token`, `refresh_token`, and `csrf_token` cookies, then redirects to the frontend dashboard
6. `POST /refresh` is still a gateway-public route, but the backend requires both the `refresh_token` cookie and a matching `X-CSRF-Token` header

This keeps PKCE state in the backend/browser session boundary while preserving the gateway's role as the single external entry point.

---

### CORS Configuration

Allowed origins for cross-origin requests:
```
http://localhost:5173  (Vite dev server)
http://localhost:5174  (Alternate Vite port)
http://localhost:3000  (React CRA)
http://localhost:8080  (Alt dev server)
http://localhost
```

**CORS Headers:**
| Header | Value |
|--------|-------|
| `Access-Control-Allow-Methods` | GET, POST, PUT, DELETE, OPTIONS |
| `Access-Control-Allow-Headers` | Authorization, Content-Type, Accept, X-CSRF-Token |
| `Access-Control-Allow-Credentials` | true |
| `Access-Control-Max-Age` | 86400 (24 hours) |

---

### Rate Limiting

Token-bucket rate limiting per authenticated user or IP:

| Parameter | Value |
|-----------|-------|
| Rate | 10 requests/second |
| Burst | 20 requests |
| Store Size | 20MB shared memory |

**Behavior:**
- Authenticated users are limited by `sub` claim (user ID)
- Unauthenticated requests limited by IP address
- Excess requests receive `429 Too Many Requests`

---

### Route Configuration

#### Public Routes (No JWT Required)
| Route | Purpose |
|-------|---------|
| `/login` | Authorization Code + PKCE login initiation |
| `/logout` | Session termination |
| `/callback` | OAuth2 callback handler with state and PKCE verifier validation |
| `/refresh` | Token refresh endpoint proxied without JWT validation, but still protected by refresh cookie + CSRF checks in the backend |
| `/health` | Health check endpoint |

#### Protected Routes (JWT Required)
All other routes (`/`) require valid JWT authentication.

### Session Cookies Used By The Auth Flow

| Cookie | Set By | Purpose |
|--------|--------|---------|
| `access_token` | Backend callback / refresh | Short-lived browser session token used by the gateway for protected routes |
| `refresh_token` | Backend callback / refresh | Longer-lived token used only by the backend refresh endpoint |
| `csrf_token` | Backend callback / refresh | JavaScript-readable token for double-submit CSRF protection on `/refresh` |
| `oauth_state` | Backend login | Short-lived CSRF protection for the OAuth redirect round trip |
| `pkce_verifier` | Backend login | Short-lived PKCE secret used during the authorization code exchange |

---

## Request Flow

### 1. Preflight (OPTIONS)
```
Client ──OPTIONS──▶ Gateway ──204──▶ Client
                     │
                     └─ CORS headers added
```

### 2. Public Routes
```
Client ──/login──▶ Gateway ──proxy──▶ Backend
                     │
                     └─ No JWT validation
                     └─ Cookie passthrough enabled for state, PKCE verifier, refresh, and CSRF cookies
```

### 3. Protected Routes
```
Client ──/api/data──▶ Gateway ──JWT Valid?
                         │
                   ┌─────┴─────┐
                   │           │
                  Yes         No
                   │           │
                   ▼           ▼
              Rate Limit    401 Error
                   │
                   ▼
              Backend (with identity headers)
```

---

## Identity Headers

After successful JWT validation, the gateway injects these headers for the backend:

| Header | Source | Description |
|--------|--------|-------------|
| `X-User-ID` | `payload.sub` | Keycloak user ID |
| `X-User-Email` | `payload.email` | User email address |
| `X-User-Preferred-Username` | `payload.preferred_username` | Display username |
| `X-User-Roles` | `payload.realm_access.roles` | JSON array of roles |
| `X-Token-Exp` | `payload.exp` | Token expiration timestamp |
| `X-Token-Verified` | `"true"` | Confirmation of validation |
| `X-Gateway-Secret` | `nginx.conf` | **CRITICAL: Proves request from authenticated gateway** |

⚠️ **CRITICAL:** The `X-Gateway-Secret` header proves that the request came through the authenticated gateway. Without this header/value, the backend **MUST reject** the user identity headers as they could be spoofed by a direct HTTP client.

---

## Error Responses

| Status | Error | Cause |
|--------|-------|-------|
| `401` | Missing authentication | No token in header or cookie |
| `401` | Malformed token | Invalid JWT structure |
| `401` | Unsupported algorithm | Not RS256 |
| `401` | Key not found | JWKS doesn't contain signing key |
| `401` | Invalid signature | Cryptographic verification failed |
| `401` | Token expired | `exp` claim in past |
| `401` | Token not yet valid | `nbf` claim in future |
| `401` | Invalid issuer | `iss` not in allowed list |
| `429` | Too many requests | Rate limit exceeded |
| `503` | Auth unavailable | Cannot fetch JWKS from Keycloak |

**Error Format:**
```json
{
  "error": "Invalid signature"
}
```

---

## Docker Configuration

### Docker Compose Service
```yaml
gateway:
  build: ../gateway
  container_name: api-gateway
  ports:
    - "80:80"
  volumes:
    - ../gateway/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf
    - ../gateway/lua:/usr/local/openresty/nginx/lua
  depends_on:
    - backend
  networks:
    - app-network
```

### Network Architecture
```
┌──────────────────────────────────────────────┐
│              app-network (bridge)             │
│                                               │
│  ┌─────────┐  ┌─────────┐  ┌─────────────┐  │
│  │ gateway │  │ backend │  │   keycloak  │  │
│  │  :80    │  │  :8000  │  │    :8080    │  │
│  └────┬────┘  └────┬────┘  └──────┬──────┘  │
│       │            │               │         │
│       └────────────┴───────────────┘         │
└──────────────────────────────────────────────┘
```

---

## Shared Memory Zones

| Zone | Size | Purpose |
|------|------|---------|
| `jwks_cache` | 1MB | JWKS key caching |
| `rate_limit_store` | 20MB | Rate limiting state |

---

## Security Considerations

1. **RS256 Algorithm** - Asymmetric keys prevent token forgery without private key
2. **JWKS Caching** - Reduces load on IdP, 300-second TTL with forced refresh on key miss
3. **Claims Validation** - Validates expiration, not-before, and issuer
4. **Rate Limiting** - Prevents abuse after authentication
5. **CORS Restrictions** - Only allows specific localhost origins
6. **Network Isolation** - Backend only accessible via gateway in Docker network
7. **Gateway Secret** - All user identity headers require `X-Gateway-Secret` validation
   - Prevents header spoofing even if backend is directly accessible
   - Required in production (optional in dev with warning)
   - Must be a strong random secret (32+ characters recommended)
   - Rotated when gateway deployment updated

---

## Why OpenResty? Comparison with Alternatives

### Why We Chose OpenResty (NGINX + Lua)

| Advantage | Description |
|-----------|-------------|
| **High Performance** | NGINX's event-driven, non-blocking architecture handles 10K+ concurrent connections with minimal memory |
| **Low Latency** | Lua runs directly in NGINX worker processes - no network hop to external auth services |
| **Full Control** | Custom JWT validation logic without vendor dependencies or black-box behavior |
| **Lightweight** | ~15MB Docker image vs 100MB+ for Java-based gateways |
| **Battle-Tested** | NGINX powers 30%+ of the internet; OpenResty is used by Cloudflare, Kong, and Adobe |
| **Zero External Dependencies** | No sidecar containers, no external auth services required at runtime |
| **Cost Effective** | No per-request pricing, no licensing fees - pure open source |

### Why NOT Other Solutions

#### ❌ Cloud API Gateways (AWS, Azure, GCP)

| Factor | Cloud Gateway | OpenResty |
|--------|--------------|-----------|
| **Cost** | $3.50 per million requests + data transfer | Free (self-hosted) |
| **Vendor Lock-in** | High - proprietary config formats | None - portable NGINX config |
| **Latency** | +10-50ms (external service call) | <1ms (in-process) |
| **Customization** | Limited to provided features | Unlimited via Lua |
| **Offline Development** | Requires internet/emulators | Works fully offline |

**Verdict:** Cloud gateways add cost and latency. Best for serverless architectures, not containerized microservices.

---

#### ❌ Kong Gateway

| Factor | Kong | OpenResty (Raw) |
|--------|------|-----------------|
| **Resource Usage** | 500MB+ RAM (Postgres/Cassandra required) | 50MB RAM (stateless) |
| **Complexity** | Admin API, database migrations, plugins | Single config file + Lua script |
| **Startup Time** | 10-30 seconds | <1 second |
| **Learning Curve** | Kong-specific plugin system | Standard NGINX + Lua |
| **Debugging** | Abstracted, harder to trace | Direct access to request lifecycle |

**Verdict:** Kong is overkill for single-service gateways. It's designed for enterprise multi-team API management, not lightweight authentication proxies.

---

#### ❌ Traefik

| Factor | Traefik | OpenResty |
|--------|---------|-----------|
| **JWT Validation** | Basic (ForwardAuth required) | Full RS256/JWKS built-in |
| **Custom Logic** | Requires external middleware service | Inline Lua scripting |
| **Configuration** | YAML/TOML + labels | nginx.conf (industry standard) |
| **Identity Headers** | Limited without plugins | Fully customizable |

**Verdict:** Traefik excels at dynamic service discovery (Kubernetes, Docker Swarm) but lacks native JWT validation. ForwardAuth adds latency and complexity.

---

#### ❌ Envoy Proxy

| Factor | Envoy | OpenResty |
|--------|-------|-----------|
| **Configuration** | Complex YAML (xDS, listeners, clusters) | Simple nginx.conf |
| **Learning Curve** | Steep - service mesh concepts | Moderate - familiar NGINX |
| **Resource Usage** | Higher (C++ but feature-heavy) | Lower |
| **Use Case** | Service mesh sidecar | Edge gateway |

**Verdict:** Envoy is designed for service mesh architectures (Istio, Consul Connect). Overkill for a simple edge gateway with JWT validation.

---

#### ❌ Express.js / FastAPI Middleware

| Factor | App-Level Middleware | Gateway |
|--------|---------------------|---------|
| **Separation of Concerns** | Auth logic mixed with business logic | Clean separation |
| **Reusability** | Must duplicate across microservices | Single point of enforcement |
| **Performance** | Node/Python single-threaded | NGINX multi-worker |
| **Fail-Open Risk** | Possible if middleware misconfigured | Gateway blocks before backend |

**Verdict:** Application-level auth doesn't scale across services and can be bypassed if misconfigured. Gateway provides defense-in-depth.

---

#### ❌ Spring Cloud Gateway

| Factor | Spring Cloud Gateway | OpenResty |
|--------|---------------------|-----------|
| **Startup Time** | 15-45 seconds (JVM warmup) | <1 second |
| **Memory** | 256MB-1GB heap | 50MB |
| **Language Dependency** | Requires Java ecosystem | Language-agnostic |
| **Docker Image Size** | 200-400MB | 15MB |

**Verdict:** Spring Cloud Gateway makes sense for Java-heavy organizations. For polyglot microservices, it adds unnecessary JVM overhead.

---

### When to Use Alternatives

| Use Case | Recommended Solution |
|----------|---------------------|
| AWS Lambda / Serverless | AWS API Gateway |
| Kubernetes with dynamic scaling | Traefik + IngressRoute |
| Full service mesh (mTLS, tracing) | Envoy + Istio |
| Enterprise API monetization | Kong Enterprise / Apigee |
| Single Python/Node service (simple) | App-level middleware |
| **Containerized microservices with JWT auth** | **OpenResty ✓** |

---

### Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                    Gateway Selection Matrix                      │
├─────────────────┬───────────┬─────────┬──────────┬─────────────┤
│                 │ OpenResty │  Kong   │ Traefik  │ Cloud GW    │
├─────────────────┼───────────┼─────────┼──────────┼─────────────┤
│ Performance     │    ★★★    │   ★★    │   ★★★    │     ★★      │
│ Simplicity      │    ★★★    │   ★     │   ★★     │     ★★★     │
│ Customization   │    ★★★    │   ★★    │   ★      │     ★       │
│ Cost            │    ★★★    │   ★★    │   ★★★    │     ★       │
│ JWT Support     │    ★★★    │   ★★★   │   ★      │     ★★★     │
│ Learning Curve  │    ★★     │   ★     │   ★★     │     ★★★     │
│ Enterprise      │    ★      │   ★★★   │   ★★     │     ★★★     │
└─────────────────┴───────────┴─────────┴──────────┴─────────────┘

★★★ = Excellent  ★★ = Good  ★ = Limited
```

**Our Choice:** OpenResty delivers the best balance of performance, simplicity, and full control for a containerized FastAPI backend with Keycloak authentication.

---

## Development Tips

### Testing JWT Validation
```bash
# Get a token from Keycloak
curl -X POST "http://localhost:8080/realms/auth-realm/protocol/openid-connect/token" \
  -d "client_id=your-client" \
  -d "client_secret=your-secret" \
  -d "grant_type=client_credentials"

# Test protected endpoint
curl -H "Authorization: Bearer <token>" http://localhost/api/endpoint
```

### Debugging
- Check gateway logs: `docker logs api-gateway`
- JWKS cache can be viewed in NGINX error logs
- Add `ngx.log(ngx.ERR, "debug message")` in Lua for debugging

### Local Development
Without Docker, configure NGINX to point to local backend:
```nginx
upstream backend_service {
    server localhost:8000;
}
```

---

## File Structure

```
gateway/
├── Dockerfile              # OpenResty image + Lua dependencies
├── nginx.conf              # Main configuration
└── lua/
    └── jwt_validator.lua   # JWT validation logic
```

---

## Deep Dive: Internal Architecture & Module Connections

This section provides minute-level details of how every component works internally and connects with other modules.

---

### Complete System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                    BROWSER / CLIENT                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                │
│  │ localStorage │  │   Cookies    │  │  fetch/XHR   │  │   Headers    │                │
│  │  (CSRF only) │  │ (httpOnly)   │  │   Client     │  │ (CORS mode)  │                │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘                │
└─────────────────────────────────────────┬───────────────────────────────────────────────┘
                                          │
                                          │ HTTP Request (Port 80)
                                          │ + access_token cookie
                                          │ + Origin header
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              API GATEWAY (OpenResty)                                     │
│                                                                                          │
│  ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                            nginx.conf (Master Config)                               │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐               │ │
│  │  │   events    │  │    http     │  │   server    │  │  location   │               │ │
│  │  │   block     │  │   block     │  │   block     │  │   blocks    │               │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘               │ │
│  └────────────────────────────────────────────────────────────────────────────────────┘ │
│                                          │                                               │
│                                          ▼                                               │
│  ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                         jwt_validator.lua (Lua Script)                              │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐               │ │
│  │  │   Token     │  │    JWKS     │  │   RS256     │  │   Claims    │               │ │
│  │  │  Extract    │  │   Fetch     │  │   Verify    │  │  Validate   │               │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘               │ │
│  └────────────────────────────────────────────────────────────────────────────────────┘ │
│                                          │                                               │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐                         │
│  │  lua_shared_dict│  │  lua_shared_dict│  │   DNS Resolver  │                         │
│  │   jwks_cache    │  │ rate_limit_store│  │   127.0.0.11    │                         │
│  │      1MB        │  │      20MB       │  │  (Docker DNS)   │                         │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘                         │
└─────────────────────────────────────────┬───────────────────────────────────────────────┘
                                          │
                                          │ proxy_pass + Identity Headers
                                          │ X-User-ID, X-User-Email, X-User-Roles...
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              FASTAPI BACKEND (Port 8000)                                 │
│                                                                                          │
│  ┌───────────────────┐     ┌───────────────────┐     ┌───────────────────┐             │
│  │    routes.py      │────▶│  dependencies.py  │────▶│   Business Logic  │             │
│  │  (API Endpoints)  │     │ (Auth Extraction) │     │    (Services)     │             │
│  └───────────────────┘     └───────────────────┘     └───────────────────┘             │
└─────────────────────────────────────────┬───────────────────────────────────────────────┘
                                          │
                                          │ JWKS Fetch (HTTP)
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              KEYCLOAK (Port 8080)                                        │
│                                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐│
│  │                              auth-realm                                              ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                ││
│  │  │   Users     │  │   Roles     │  │   Clients   │  │    JWKS     │                ││
│  │  │   Store     │  │  (realm)    │  │  (OAuth)    │  │  Endpoint   │                ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘                ││
│  └─────────────────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### Module 1: nginx.conf - The Orchestrator

The `nginx.conf` file is the **central nervous system** of the gateway. It defines:

#### 1.1 Lua Package Path
```nginx
lua_package_path "/usr/local/openresty/nginx/lua/?.lua;;";
```
**What it does:** Tells the Lua runtime where to find custom Lua modules. The `;;` at the end appends the default Lua path.

**Connection:** This is how `jwt_validator.lua` becomes accessible via `access_by_lua_file`.

#### 1.2 DNS Resolver
```nginx
resolver 127.0.0.11 valid=30s ipv6=off;
resolver_timeout 5s;
```
**What it does:**
- `127.0.0.11` is Docker's embedded DNS server
- `valid=30s` caches DNS lookups for 30 seconds
- `ipv6=off` disables IPv6 to avoid lookup delays

**Connection:** Required for `lua-resty-http` to resolve `keycloak:8080` when fetching JWKS.

#### 1.3 Shared Memory Zones
```nginx
lua_shared_dict jwks_cache 1m;
lua_shared_dict rate_limit_store 20m;
```
**What it does:** Allocates shared memory accessible by all NGINX worker processes.

**Internal Working:**
```
┌─────────────────────────────────────────────────────────┐
│                 NGINX Master Process                     │
└─────────────────────────┬───────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  Worker 1       │ │  Worker 2       │ │  Worker N       │
│  (Lua VM)       │ │  (Lua VM)       │ │  (Lua VM)       │
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
                             ▼
         ┌─────────────────────────────────────────┐
         │          Shared Memory Zone              │
         │  ┌─────────────┐  ┌─────────────────┐   │
         │  │ jwks_cache  │  │rate_limit_store │   │
         │  │   (1MB)     │  │     (20MB)      │   │
         │  └─────────────┘  └─────────────────┘   │
         └─────────────────────────────────────────┘
```

**Connection to Lua:**
```lua
local jwks_cache = ngx.shared.jwks_cache  -- Access shared dict
jwks_cache:set("jwks", data, 300)         -- Set with 300s TTL
local cached = jwks_cache:get("jwks")     -- Get cached value
```

#### 1.4 Upstream Definition
```nginx
upstream backend_service {
    server backend:8000;
}
```
**What it does:** Defines the backend server pool for load balancing.

**Internal DNS Resolution:**
```
"backend"  ──▶  Docker DNS (127.0.0.11)  ──▶  172.18.0.3:8000
                                               (Container IP)
```

#### 1.5 Location Blocks Hierarchy & Header Injection

```
┌─────────────────────────────────────────────────────────────────┐
│                        server { listen 80; }                     │
├─────────────────────────────────────────────────────────────────┤
│  location ~ ^/(login|logout|callback|refresh) {                 │
│      # REGEX match - public OAuth routes                         │
│      # NO jwt_validator.lua - bypasses authentication            │
│      proxy_pass http://backend_service;                          │
│  }                                                               │
├─────────────────────────────────────────────────────────────────┤
│  location /health {                                              │
│      # PREFIX match - health check                               │
│      # NO jwt_validator.lua - always accessible                  │
│      proxy_pass http://backend_service/health;                   │
│  }                                                               │
├─────────────────────────────────────────────────────────────────┤
│  location / {                                                    │
│      # DEFAULT match - all other routes (lowest priority)        │
│      # PROTECTED - runs jwt_validator.lua                        │
│      access_by_lua_file jwt_validator.lua;                       │
│      proxy_pass http://backend_service;                          │
│                                                                  │
│      # 🔒 CRITICAL: Inject gateway secret on ALL requests       │
│      # This proves request came from authenticated gateway       │
│      proxy_set_header X-Gateway-Secret "my-gateway-secret";      │
│  }                                                               │
└─────────────────────────────────────────────────────────────────┘
```

**NGINX Location Matching Order:**
1. Exact match (`= /path`) - highest priority
2. Preferential prefix (`^~ /path`)
3. Regex match (`~ pattern` or `~* pattern`) - case sensitive/insensitive
4. Prefix match (`/path`)
5. Default (`/`) - lowest priority

**Header Injection Flow:**
```
┌─────────────────────────────────────────────────────────────────┐
│  After JWT validation succeeds:                                │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │ 1. jwt_validator.lua validates token                     │ │
│  │ 2. Lua sets X-User-* headers                             │ │
│  │ 3. nginx.conf adds X-Gateway-Secret for ALL routes       │ │
│  │ 4. proxy_pass sends to backend with all headers          │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                │
│  Backend receives:                                            │
│  ├─ X-User-ID: abc123                                        │
│  ├─ X-User-Email: user@example.com                           │
│  ├─ X-User-Roles: ["user","admin"]                           │
│  ├─ X-Token-Exp: 1741043180                                  │
│  └─ X-Gateway-Secret: my-gateway-secret ← Proof of origin   │
└─────────────────────────────────────────────────────────────────┘
```

---

### Module 2: jwt_validator.lua - The Security Core

This Lua script runs **inside the NGINX worker process** during the `access` phase, before the request reaches the backend.

#### 2.1 NGINX Request Phases

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     NGINX Request Processing Phases                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. POST_READ      ──▶  Read request from client                        │
│         │                                                                │
│         ▼                                                                │
│  2. SERVER_REWRITE ──▶  Server-level rewrites                           │
│         │                                                                │
│         ▼                                                                │
│  3. FIND_CONFIG    ──▶  Select location block                           │
│         │                                                                │
│         ▼                                                                │
│  4. REWRITE        ──▶  Location-level rewrites                         │
│         │                                                                │
│         ▼                                                                │
│  ╔═════════════════════════════════════════════════════════════════╗    │
│  ║ 5. ACCESS       ──▶  ★ jwt_validator.lua runs HERE ★            ║    │
│  ║                      access_by_lua_file directive               ║    │
│  ║                      Can BLOCK request with ngx.exit(401)       ║    │
│  ╚═════════════════════════════════════════════════════════════════╝    │
│         │                                                                │
│         ▼                                                                │
│  6. CONTENT        ──▶  proxy_pass to backend                           │
│         │                                                                │
│         ▼                                                                │
│  7. LOG            ──▶  Access logging                                  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 2.2 Token Extraction Logic

```lua
-- Priority 1: Authorization Header
local auth = ngx.var.http_authorization
if auth then
    token = string.match(auth, "Bearer%s+(.+)")
end

-- Priority 2: Cookie fallback
if not token then
    token = ngx.var.cookie_access_token
end
```

**Flow Diagram:**
```
┌─────────────────────────────────────────────────────────────────┐
│                    Token Extraction Flow                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Request Headers                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI...      │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│                              ▼                                   │
│            ┌─────────────────────────────────┐                  │
│            │  string.match(auth, "Bearer%s+(.+)")               │
│            │  Regex extracts token after "Bearer "              │
│            └─────────────────────────────────┘                  │
│                              │                                   │
│              Found? ─────────┼─────────── Not Found?            │
│                │             │                    │              │
│                ▼             │                    ▼              │
│          Use Header Token    │          Check Cookie             │
│                              │     ┌─────────────────────────┐  │
│                              │     │Cookie: access_token=eyJ.│  │
│                              │     └─────────────────────────┘  │
│                              │                    │              │
│                              │                    ▼              │
│                              │          ngx.var.cookie_access_token
│                              │                    │              │
│                              ▼                    ▼              │
│                         ┌────────────────────────────┐          │
│                         │      Final Token Value      │          │
│                         └────────────────────────────┘          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### 2.3 JWT Structure Parsing

```
JWT Token Format: HEADER.PAYLOAD.SIGNATURE

eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InZNYWN...  (Header - Base64URL)
.
eyJleHAiOjE3NDEwNDMxODAsImlhdCI6MTc0MTA0Mjg4MCwianRp...  (Payload - Base64URL)
.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c...           (Signature - Base64URL)
```

**Parsing Flow:**
```lua
-- Split by '.' delimiter
local parts = {}
for part in string.gmatch(token, "[^%.]+") do
    table.insert(parts, part)
end
-- parts[1] = header_b64
-- parts[2] = payload_b64  
-- parts[3] = sig_b64
```

**Base64URL Decoding:**
```lua
local function base64url_decode(input)
    -- Add padding if needed (Base64URL omits '=' padding)
    local remainder = #input % 4
    if remainder > 0 then
        input = input .. string.rep("=", 4 - remainder)
    end
    -- Convert Base64URL to standard Base64
    input = input:gsub("-", "+"):gsub("_", "/")
    -- Decode
    return ngx.decode_base64(input)
end
```

```
Base64URL ──▶ Standard Base64 ──▶ Binary/JSON

"-" ───────▶ "+"
"_" ───────▶ "/"
(no padding) ▶ (add "=" padding)
```

#### 2.4 JWKS Fetching & Caching

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          JWKS Fetch Flow                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Check Cache                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ local cached = jwks_cache:get("jwks")                               ││
│  │ if cached then return cjson.decode(cached) end                      ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                              │                                           │
│              Cache Hit ──────┴────── Cache Miss                         │
│                  │                        │                              │
│                  ▼                        ▼                              │
│           Return Cached            2. HTTP Request to Keycloak          │
│                                    ┌────────────────────────────────────┐│
│                                    │ GET /realms/auth-realm/            ││
│                                    │     protocol/openid-connect/certs  ││
│                                    │ Host: keycloak:8080                ││
│                                    └────────────────────────────────────┘│
│                                                    │                     │
│                                                    ▼                     │
│                                    3. Keycloak Response (JWKS)          │
│                                    ┌────────────────────────────────────┐│
│                                    │ {                                  ││
│                                    │   "keys": [                        ││
│                                    │     {                              ││
│                                    │       "kid": "vMac...",            ││
│                                    │       "kty": "RSA",                ││
│                                    │       "alg": "RS256",              ││
│                                    │       "use": "sig",                ││
│                                    │       "n": "0vx7agoeb...",         ││
│                                    │       "e": "AQAB"                  ││
│                                    │     }                              ││
│                                    │   ]                                ││
│                                    │ }                                  ││
│                                    └────────────────────────────────────┘│
│                                                    │                     │
│                                                    ▼                     │
│                                    4. Cache with TTL                    │
│                                    ┌────────────────────────────────────┐│
│                                    │ jwks_cache:set("jwks", body, 300)  ││
│                                    │ -- 300 seconds = 5 minutes TTL     ││
│                                    └────────────────────────────────────┘│
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key Rotation Handling:**
```lua
-- First attempt: use cached JWKS
local jwk = find_key_by_kid(jwks, header.kid)

-- Key ID not found? Force refresh (key rotation scenario)
if not jwk then
    jwks = fetch_jwks(true)  -- force=true bypasses cache
    jwk = find_key_by_kid(jwks, header.kid)
end
```

#### 2.5 JWK to PEM Conversion (Deep Dive)

Keycloak provides keys in JWK (JSON Web Key) format, but OpenSSL requires PEM format.

**JWK Structure (RSA Public Key):**
```json
{
  "kty": "RSA",
  "kid": "vMacXGRPqV...",
  "use": "sig",
  "alg": "RS256",
  "n": "0vx7agoebGcQSu...",  // Modulus (Base64URL)
  "e": "AQAB"                 // Exponent (Base64URL)
}
```

**Conversion Process:**
```
┌─────────────────────────────────────────────────────────────────────────┐
│                      JWK to PEM Conversion                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Step 1: Decode Base64URL values                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ n = base64url_decode(jwk.n)  -- 256 bytes (2048-bit key)           ││
│  │ e = base64url_decode(jwk.e)  -- Usually 3 bytes (65537 = 0x010001) ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                              │                                           │
│                              ▼                                           │
│  Step 2: ASN.1 DER Encoding (SubjectPublicKeyInfo)                      │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ SEQUENCE {                              -- Outer wrapper            ││
│  │   SEQUENCE {                            -- Algorithm identifier     ││
│  │     OID 1.2.840.113549.1.1.1            -- rsaEncryption            ││
│  │     NULL                                                            ││
│  │   }                                                                 ││
│  │   BIT STRING {                          -- Public key data          ││
│  │     SEQUENCE {                          -- RSA public key           ││
│  │       INTEGER n                         -- Modulus                  ││
│  │       INTEGER e                         -- Exponent                 ││
│  │     }                                                               ││
│  │   }                                                                 ││
│  │ }                                                                   ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                              │                                           │
│                              ▼                                           │
│  Step 3: Base64 encode DER                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ local b64 = ngx.encode_base64(der)                                  ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                              │                                           │
│                              ▼                                           │
│  Step 4: Wrap in PEM format                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ -----BEGIN PUBLIC KEY-----                                          ││
│  │ MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSu...      ││
│  │ ...                                                                 ││
│  │ -----END PUBLIC KEY-----                                            ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**ASN.1 Length Encoding:**
```lua
local function encode_length(len)
    if len < 128 then
        return string.char(len)              -- Short form: 1 byte
    elseif len < 256 then
        return string.char(0x81, len)        -- Long form: 0x81 + 1 byte
    else
        return string.char(0x82,             -- Long form: 0x82 + 2 bytes
                           math.floor(len / 256), 
                           len % 256)
    end
end
```

#### 2.6 RS256 Signature Verification (FFI Deep Dive)

The script uses LuaJIT FFI (Foreign Function Interface) to call OpenSSL directly.

**FFI Declarations:**
```lua
ffi.cdef[[
    typedef struct bio_st BIO;           // OpenSSL I/O abstraction
    typedef struct evp_pkey_st EVP_PKEY; // Generic key container
    typedef struct evp_md_ctx_st EVP_MD_CTX; // Message digest context
    
    // Create memory buffer BIO from PEM string
    BIO *BIO_new_mem_buf(const void *buf, int len);
    
    // Parse PEM and extract public key
    EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x, void *cb, void *u);
    
    // Get SHA-256 digest algorithm
    const EVP_MD *EVP_sha256(void);
    
    // Initialize verification context
    int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, ...);
    
    // Feed data to verify
    int EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
    
    // Verify signature
    int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen);
]]

local crypto = ffi.load("crypto")  -- Load libcrypto.so
```

**Verification Flow:**
```
┌─────────────────────────────────────────────────────────────────────────┐
│                    RS256 Signature Verification                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  JWT Token:  HEADER . PAYLOAD . SIGNATURE                               │
│              ─────────────────   ─────────                              │
│                Signing Input     What to verify                         │
│                                                                          │
│  Step 1: Prepare signing input                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ signing_input = header_b64 .. "." .. payload_b64                    ││
│  │ -- This is EXACTLY what Keycloak signed                             ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                              │                                           │
│                              ▼                                           │
│  Step 2: Load PEM public key into OpenSSL                               │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ bio = BIO_new_mem_buf(pem, #pem)     -- Create memory buffer        ││
│  │ pkey = PEM_read_bio_PUBKEY(bio,...)  -- Parse PEM to EVP_PKEY       ││
│  │ BIO_free(bio)                        -- Clean up buffer             ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                              │                                           │
│                              ▼                                           │
│  Step 3: Initialize digest verification                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ ctx = EVP_MD_CTX_new()                                              ││
│  │ EVP_DigestVerifyInit(ctx, nil, EVP_sha256(), nil, pkey)             ││
│  │ -- Sets up: SHA256 hash + RSA verification with public key          ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                              │                                           │
│                              ▼                                           │
│  Step 4: Feed signing input to hasher                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ EVP_DigestVerifyUpdate(ctx, signing_input, #signing_input)          ││
│  │ -- Computes SHA256(signing_input)                                   ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                              │                                           │
│                              ▼                                           │
│  Step 5: Verify signature matches                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ result = EVP_DigestVerifyFinal(ctx, signature, #signature)          ││
│  │ -- Decrypts signature with public key                               ││
│  │ -- Compares decrypted hash with computed hash                       ││
│  │ -- Returns 1 if valid, 0 if invalid                                 ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                              │                                           │
│                              ▼                                           │
│  Step 6: Cleanup                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ EVP_MD_CTX_free(ctx)                                                ││
│  │ EVP_PKEY_free(pkey)                                                 ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Cryptographic Math (Simplified):**
```
RS256 = RSASSA-PKCS1-v1_5 using SHA-256

Signing (Keycloak):
1. hash = SHA256("header.payload")
2. signature = RSA_SIGN(hash, private_key)

Verification (Gateway):
1. hash = SHA256("header.payload")  -- Recompute
2. expected_hash = RSA_VERIFY(signature, public_key)  -- Decrypt
3. valid = (hash == expected_hash)
```

#### 2.7 Rate Limiting Implementation

```lua
local limiter, err = limit_req.new(rate_store, 10, 20)
-- rate_store = "rate_limit_store" (shared memory zone)
-- 10 = requests per second
-- 20 = burst allowance
```

**Token Bucket Algorithm:**
```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Token Bucket Rate Limiting                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Configuration: rate=10/s, burst=20                                     │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │                         TOKEN BUCKET                                 ││
│  │  ┌─────────────────────────────────────────┐                        ││
│  │  │  ● ● ● ● ● ● ● ● ● ● ● ● ● ● ● ● ● ● ● ● │  Max 30 tokens       ││
│  │  │  (20 burst + 10 base)                     │  (rate + burst)      ││
│  │  └─────────────────────────────────────────┘                        ││
│  │                    ▲                                                 ││
│  │                    │ Refill: 10 tokens/second                       ││
│  │                    │                                                 ││
│  │  Request arrives ──┼──▶ Token available? ────┬──▶ YES: Process     ││
│  │                    │                          │       (take token)  ││
│  │                    │                          │                      ││
│  │                    │                          └──▶ NO: 429 Error    ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
│  Key Selection:                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ local key = payload.sub or ngx.var.binary_remote_addr              ││
│  │ -- Authenticated: limit by user ID (sub claim)                      ││
│  │ -- Unauthenticated: limit by IP address                             ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
│  Delay Handling:                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ if delay > 0 then                                                   ││
│  │     ngx.sleep(delay)  -- Smooth traffic instead of hard reject      ││
│  │ end                                                                 ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 2.8 Identity Header Injection

After successful validation, Lua injects headers for the backend:

```lua
ngx.req.set_header("X-User-ID", payload.sub or "")
ngx.req.set_header("X-User-Email", payload.email or "")
ngx.req.set_header("X-User-Preferred-Username", payload.preferred_username or "")
ngx.req.set_header("X-User-Roles", cjson.encode(payload.realm_access.roles) or "[]")
ngx.req.set_header("X-Token-Exp", tostring(payload.exp or 0))
ngx.req.set_header("X-Token-Verified", "true")
```

**Header Flow:**
```
┌──────────────────────────────────────────────────────────────────────────┐
│  Original Request Headers          │  Injected Gateway Headers           │
├────────────────────────────────────┼────────────────────────────────────┤
│  Authorization: Bearer eyJhb...    │  X-User-ID: abc123-def456          │
│  Content-Type: application/json    │  X-User-Email: user@example.com    │
│  Origin: http://localhost:5173     │  X-User-Preferred-Username: jdoe   │
│                                    │  X-User-Roles: ["user","admin"]    │
│                                    │  X-Token-Exp: 1741043180           │
│                                    │  X-Token-Verified: true            │
└────────────────────────────────────┴────────────────────────────────────┘
                                    │
                                    ▼
                         Backend receives BOTH sets
```

---

### Module 3: Backend Integration (dependencies.py)

The FastAPI backend reads gateway-injected headers:

```python
async def get_gateway_user(request: Request):
    """Extract user from gateway-injected headers."""
    
    # 🔒 CRITICAL: Validate gateway authentication first
    # Without this, anyone sending X-User-ID headers directly could spoof identity
    if settings.GATEWAY_SECRET:
        gateway_secret = request.headers.get("X-Gateway-Secret")
        if not gateway_secret or gateway_secret != settings.GATEWAY_SECRET:
            logger.warning(f"Rejected request without valid gateway secret")
            return None  # Reject - not from authenticated gateway
    
    # Extract identity from headers
    user_id = request.headers.get("X-User-ID")
    if not user_id:
        return None
    
    # Parse roles JSON
    roles = json.loads(request.headers.get("X-User-Roles", "[]"))
    
    return {
        "sub": user_id,
        "email": request.headers.get("X-User-Email"),
        "preferred_username": request.headers.get("X-User-Preferred-Username"),
        "roles": roles,
        "exp": int(request.headers.get("X-Token-Exp", 0)),
    }
```

**Security Model:**
```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Network-Level Security + Header Auth                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ATTACK SCENARIO 1 (Direct HTTP call with spoofed headers):            │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │  Attacker: curl -H "X-User-ID: admin" http://backend:8000/me      ││
│  │  Backend checks: Is X-Gateway-Secret header present and valid?     ││
│  │  Result: ❌ NO → 401 Unauthorized                                   ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                         │
│  ATTACK SCENARIO 2 (Legitimate gateway request):                        │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │  Gateway: curl -H "X-User-ID: admin" \                             ││
│  │              -H "X-Gateway-Secret: <secret>" http://backend:8000   ││
│  │  Backend checks: Is X-Gateway-Secret valid?                       ││
│  │  Result: ✅ YES → Accept user identity                             ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                         │
│  DEFENSE LAYERS:                                                        │
│  1. Network Isolation: Backend only in Docker network                  │
│  2. Gateway Secret: Request must include exact secret value            │
│  3. Both required: Forged headers cannot reach backend                 │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Configuration:**
```bash
# Development (secret optional, logs warning)
# Set nothing: GATEWAY_SECRET will be None

# Production (secret required)
export GATEWAY_SECRET="your-super-secret-random-key-min-32-chars"
```

---

### Module 4: OAuth Flow Integration (routes.py)

The gateway handles OAuth routes **without** JWT validation:

```nginx
location ~ ^/(login|logout|callback|refresh) {
    # NO access_by_lua_file - public routes
    proxy_pass http://backend_service;
}
```

**Complete OAuth Flow:**
```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                         OAuth 2.0 Authorization Code + PKCE Flow                          │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│  ① User clicks "Login"                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐│
│  │  Browser ──GET /login──▶ Gateway ──proxy──▶ Backend                                ││
│  │                                              │                                       ││
│  │                                              ▼                                       ││
│  │                                    Generate state token                              ││
│  │                                    Generate PKCE verifier/challenge                  ││
│  │                                    Set oauth_state cookie                            ││
│  │                                    Set pkce_verifier cookie                          ││
│  │                                    Redirect to Keycloak                              ││
│  └─────────────────────────────────────────────────────────────────────────────────────┘│
│                                                                                          │
│  ② User authenticates with Keycloak                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐│
│  │  Browser ──▶ Keycloak login page                                                    ││
│  │  User enters credentials                                                            ││
│  │  Keycloak validates                                                                 ││
│  │  Keycloak redirects to: /callback?code=ABC123&state=XYZ789                         ││
│  └─────────────────────────────────────────────────────────────────────────────────────┘│
│                                                                                          │
│  ③ Callback handler                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐│
│  │  Browser ──GET /callback?code=ABC&state=XYZ──▶ Gateway ──proxy──▶ Backend         ││
│  │                                                                   │                 ││
│  │                                                                   ▼                 ││
│  │                                                   Verify state matches cookie       ││
│  │                                                   Load PKCE verifier from cookie    ││
│  │                                                   Exchange code for tokens          ││
│  │                                                   ┌───────────────────────────────┐││
│  │                                                   │ POST /token to Keycloak       │││
│  │                                                   │ grant_type=authorization_code │││
│  │                                                   │ code=ABC123                   │││
│  │                                                   │ code_verifier=<stored secret>  │││
│  │                                                   │ client_secret=...             │││
│  │                                                   └───────────────────────────────┘││
│  │                                                                   │                 ││
│  │                                                                   ▼                 ││
│  │                                                   Set httpOnly cookies:             ││
│  │                                                   - access_token (5min)            ││
│  │                                                   - refresh_token (7 days)         ││
│  │                                                   - csrf_token (JS readable)       ││
│  │                                                   Redirect to /dashboard           ││
│  └─────────────────────────────────────────────────────────────────────────────────────┘│
│                                                                                          │
│  ④ Subsequent API calls (protected)                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐│
│  │  Browser ──GET /api/data──▶ Gateway                                                ││
│  │                              │                                                      ││
│  │                              ▼                                                      ││
│  │                    jwt_validator.lua executes                                       ││
│  │                    Reads access_token from cookie                                   ││
│  │                    Validates RS256 signature                                        ││
│  │                    Injects X-User-* headers                                         ││
│  │                              │                                                      ││
│  │                              ▼                                                      ││
│  │                    Backend ──▶ Process request with user identity                  ││
│  └─────────────────────────────────────────────────────────────────────────────────────┘│
│                                                                                          │
│  ⑤ Token refresh (before expiry)                                                       │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐│
│  │  Browser ──POST /refresh──▶ Gateway ──proxy──▶ Backend                             ││
│  │  Headers: X-CSRF-Token: <csrf>                  │                                   ││
│  │  Cookies: refresh_token, csrf_token             ▼                                   ││
│  │                                        Validate CSRF                                ││
│  │                                        Exchange refresh_token                       ││
│  │                                        Set new access_token cookie                  ││
│  │                                        Rotate refresh_token and csrf_token          ││
│  └─────────────────────────────────────────────────────────────────────────────────────┘│
│                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### Module 5: Docker Network Architecture

```yaml
# docker-compose.yml
networks:
  app-network:
    driver: bridge
```

**Container DNS Resolution:**
```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Docker Bridge Network (app-network)                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Docker DNS Server: 127.0.0.11                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │  "keycloak"  ──▶  172.18.0.2                                        ││
│  │  "backend"   ──▶  172.18.0.3                                        ││
│  │  "gateway"   ──▶  172.18.0.4                                        ││
│  │  "postgres"  ──▶  172.18.0.5                                        ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
│  Port Mappings (Host:Container):                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │  gateway:    80:80    (HTTP entry point)                            ││
│  │  keycloak:   8080:8080 (IdP admin + auth)                           ││
│  │  backend:    8000:8000 (direct access for debugging)                ││
│  │  postgres:   5432:5432 (database)                                   ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Service Dependencies:**
```
┌─────────┐
│postgres │ ← Starts first (no dependencies)
└────┬────┘
     │
     ▼
┌─────────┐
│keycloak │ ← Depends on: postgres
│         │   Waits for postgres to be ready
└────┬────┘
     │
     ▼
┌─────────┐
│ backend │ ← Depends on: keycloak
│         │   Needs Keycloak for token exchange
└────┬────┘
     │
     ▼
┌─────────┐
│ gateway │ ← Depends on: backend
│         │   Needs backend for health checks
└─────────┘
```

---

### Module 6: Dockerfile Build Process

```dockerfile
FROM openresty/openresty:alpine-fat

# Install Lua modules via OPM (OpenResty Package Manager)
RUN opm get ledgetech/lua-resty-http        # HTTP client for JWKS
RUN opm get jkeys089/lua-resty-hmac         # HMAC operations
RUN opm get openresty/lua-resty-string      # String utilities  
RUN opm get cdbattags/lua-resty-jwt         # JWT parsing
RUN opm get openresty/lua-resty-limit-traffic  # Rate limiting
```

**Module Dependencies:**
```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Lua Module Dependency Graph                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  jwt_validator.lua                                                       │
│  ├── require "resty.http"        ── HTTP requests to Keycloak           │
│  ├── require "cjson"             ── JSON parsing (built-in)             │
│  ├── require "ffi"               ── OpenSSL bindings (built-in)         │
│  └── require "resty.limit.req"   ── Token bucket rate limiter           │
│                                                                          │
│  Not directly used but installed:                                        │
│  ├── lua-resty-hmac              ── For HS256 (if needed)               │
│  ├── lua-resty-string            ── String manipulation                 │
│  └── lua-resty-jwt               ── Alternative JWT library             │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

### Complete Request Timeline

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                    Request Timeline: GET /api/users (Protected)                          │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│  T+0ms    Browser sends request                                                         │
│           ├── GET /api/users HTTP/1.1                                                   │
│           ├── Host: localhost                                                           │
│           ├── Cookie: access_token=eyJhbG...                                           │
│           └── Origin: http://localhost:5173                                            │
│                                                                                          │
│  T+1ms    NGINX receives request (gateway:80)                                          │
│           ├── POST_READ phase: read full request                                        │
│           ├── SERVER_REWRITE: process server-level directives                          │
│           └── FIND_CONFIG: match location / (default)                                  │
│                                                                                          │
│  T+2ms    CORS check (nginx.conf)                                                       │
│           ├── $http_origin matches localhost:5173                                       │
│           └── Set $cors_origin variable                                                │
│                                                                                          │
│  T+3ms    ACCESS phase: jwt_validator.lua starts                                       │
│           ├── Extract token from cookie                                                │
│           ├── Parse JWT: header.payload.signature                                      │
│           └── Decode header: {"alg":"RS256","kid":"vMac..."}                          │
│                                                                                          │
│  T+4ms    JWKS cache check                                                              │
│           ├── ngx.shared.jwks_cache:get("jwks")                                        │
│           └── Cache HIT: return cached JWKS                                            │
│                                                                                          │
│  T+5ms    Find key by kid                                                               │
│           ├── Iterate jwks.keys                                                        │
│           └── Match kid="vMac..." with use="sig"                                       │
│                                                                                          │
│  T+6ms    Convert JWK to PEM                                                            │
│           ├── Decode n, e from Base64URL                                               │
│           ├── Encode ASN.1 DER structure                                               │
│           └── Wrap in PEM format                                                       │
│                                                                                          │
│  T+8ms    RS256 signature verification (OpenSSL FFI)                                   │
│           ├── BIO_new_mem_buf: load PEM                                                │
│           ├── PEM_read_bio_PUBKEY: parse to EVP_PKEY                                   │
│           ├── EVP_DigestVerifyInit: setup SHA256+RSA                                   │
│           ├── EVP_DigestVerifyUpdate: hash header.payload                              │
│           ├── EVP_DigestVerifyFinal: verify signature                                  │
│           └── Cleanup: free ctx, pkey, bio                                             │
│                                                                                          │
│  T+10ms   Claims validation                                                             │
│           ├── Check exp > now (not expired)                                            │
│           ├── Check nbf < now (already valid)                                          │
│           └── Check iss in EXPECTED_ISSUERS                                            │
│                                                                                          │
│  T+11ms   Rate limiting check                                                           │
│           ├── key = payload.sub (user ID)                                              │
│           ├── limiter:incoming(key, true)                                              │
│           └── Within limit: proceed                                                    │
│                                                                                          │
│  T+12ms   Inject identity headers                                                       │
│           ├── X-User-ID: abc123                                                        │
│           ├── X-User-Email: user@example.com                                           │
│           ├── X-User-Roles: ["user","admin"]                                           │
│           ├── X-Token-Exp: 1741043180                                                  │
│           └── X-Token-Verified: true                                                   │
│                                                                                          │
│  T+13ms   ACCESS phase complete, proceed to CONTENT                                    │
│                                                                                          │
│  T+14ms   proxy_pass to backend:8000                                                   │
│           ├── DNS resolve "backend" via 127.0.0.11                                     │
│           ├── Connect to 172.18.0.3:8000                                               │
│           └── Forward request with injected headers                                    │
│                                                                                          │
│  T+15ms   FastAPI receives request                                                      │
│           ├── routes.py: @router.get("/api/users")                                     │
│           ├── Depends(require_auth)                                                    │
│           └── get_gateway_user(request)                                                │
│                                                                                          │
│  T+16ms   Backend auth extraction (dependencies.py)                                    │
│           ├── Extract X-User-ID, X-User-Email, etc.                                   │
│           └── Parse X-User-Roles JSON                                                  │
│                                                                                          │
│  T+17ms   require_auth validation                                                       │
│           ├── Check user is not None                                                   │
│           └── Check exp > current_time                                                 │
│                                                                                          │
│  T+20ms   Business logic executes                                                       │
│           └── Return user list                                                         │
│                                                                                          │
│  T+25ms   Response flows back                                                           │
│           ├── Backend → Gateway (proxy response)                                       │
│           ├── Gateway adds CORS headers                                                │
│           └── Gateway → Browser                                                        │
│                                                                                          │
│  T+30ms   Browser receives response                                                     │
│           └── 200 OK with JSON payload                                                 │
│                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘

Total latency: ~30ms (varies based on network, caching, backend processing)
Gateway overhead: ~15ms (mostly cryptographic operations)
```

---

### Error Handling Matrix

| Phase | Error Condition | HTTP Status | Error Message | Logged? |
|-------|----------------|-------------|---------------|---------|
| Token Extract | No header or cookie | 401 | Missing authentication | No |
| Token Parse | Not 3 parts | 401 | Malformed token | No |
| Header Decode | Invalid Base64 | 401 | Malformed token | No |
| Algorithm Check | Not RS256 | 401 | Unsupported algorithm | No |
| JWKS Fetch | Keycloak unreachable | 503 | Auth unavailable | Yes (ERR) |
| Key Lookup | kid not in JWKS | 401 | Key not found | No |
| Signature | Verification fails | 401 | Invalid signature | No |
| Expiry | exp < now | 401 | Token expired | No |
| Not Before | nbf > now | 401 | Token not yet valid | No |
| Issuer | iss not in list | 401 | Invalid issuer | No |
| Rate Limit | Bucket empty | 429 | Too many requests | No |
| Backend | Token expired (double-check) | 401 | Token expired | Yes (WARN) |

---

### Memory Layout

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    NGINX Memory Architecture                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Master Process (root)                                                   │
│  ├── Configuration parsing                                               │
│  ├── Worker process management                                           │
│  └── Shared memory allocation                                            │
│      ├── jwks_cache (1MB)                                                │
│      │   └── "jwks" → JSON string (typically 2-4KB)                     │
│      └── rate_limit_store (20MB)                                         │
│          └── {user_id} → {tokens, last_update} (per user: ~100 bytes)  │
│                                                                          │
│  Worker Process 1 (nginx user)                                           │
│  ├── LuaJIT VM                                                           │
│  │   ├── Compiled Lua bytecode (~50KB)                                  │
│  │   └── FFI bindings to libcrypto                                      │
│  ├── Request state (per connection)                                      │
│  │   ├── ngx.var.* (request variables)                                  │
│  │   ├── ngx.req.* (request object)                                     │
│  │   └── Local Lua variables                                            │
│  └── Connection pool to backend                                          │
│                                                                          │
│  Worker Process 2...N (same structure)                                   │
│                                                                          │
│  Total Memory Usage:                                                     │
│  ├── Shared: ~21MB (caches)                                             │
│  ├── Per Worker: ~10MB (Lua VM + connections)                           │
│  └── Total (4 workers): ~61MB                                           │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

### Configuration Reference

| Variable | Location | Default | Description |
|----------|----------|---------|-------------|
| `JWKS_URL` | jwt_validator.lua | `http://keycloak:8080/realms/auth-realm/...` | JWKS endpoint |
| `EXPECTED_ISSUERS` | jwt_validator.lua | keycloak:8080, localhost:8080 | Valid token issuers |
| `JWKS_CACHE_TTL` | jwt_validator.lua | 300 | JWKS cache duration (seconds) |
| `rate` | jwt_validator.lua | 10 | Requests per second |
| `burst` | jwt_validator.lua | 20 | Burst allowance |
| `jwks_cache` | nginx.conf | 1m | Shared memory for JWKS |
| `rate_limit_store` | nginx.conf | 20m | Shared memory for rate limiting |
| `GATEWAY_SECRET` | nginx.conf | (hardcoded) | Secret value for X-Gateway-Secret header - should be passed as env var |

**Gateway Secret Configuration (CRITICAL FOR PRODUCTION):**

The `X-Gateway-Secret` header value is currently hardcoded in `nginx.conf`:
```nginx
proxy_set_header X-Gateway-Secret "my-gateway-secret";
```

**For production deployments, this MUST be:**
1. Read from environment variable
2. Set to strong random value (32+ chars)
3. Only known to gateway + backend
4. Rotated on each deployment

**Recommended approach:**
```nginx
# In nginx.conf (with environment variable support)
set $gateway_secret "$ENV{GATEWAY_SECRET}";
proxy_set_header X-Gateway-Secret $gateway_secret;
```

Docker Compose example:
```yaml
gateway:
  environment:
    - GATEWAY_SECRET=${GATEWAY_SECRET}
backend:
  environment:
    - GATEWAY_SECRET=${GATEWAY_SECRET}
```
