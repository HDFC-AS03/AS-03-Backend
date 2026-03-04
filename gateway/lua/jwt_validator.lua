-- ============================================================
-- Enterprise JWT Validator with RS256 Signature Verification
-- Gateway: OpenResty | IdP: Keycloak | Algorithm: RS256
-- Uses OpenSSL FFI for cryptographic signature verification
-- ============================================================

local http = require "resty.http"
local cjson = require "cjson"
local ffi = require "ffi"

-- ============================================================
-- Configuration
-- ============================================================
local JWKS_URL = "http://keycloak:8080/realms/auth-realm/protocol/openid-connect/certs"
-- Accept both internal (Docker) and external (localhost) issuers
local EXPECTED_ISSUERS = {
    ["http://keycloak:8080/realms/auth-realm"] = true,
    ["http://localhost:8080/realms/auth-realm"] = true,
}
local EXPECTED_AUD = nil  -- Set to client_id for audience validation, nil to skip
local JWKS_CACHE_TTL = 300  -- 5 minutes

-- JWKS cache (configured in nginx.conf: lua_shared_dict jwks_cache 1m)
local jwks_cache = ngx.shared.jwks_cache

-- ============================================================
-- OpenSSL FFI Declarations
-- ============================================================
ffi.cdef[[
    typedef struct bio_st BIO;
    typedef struct evp_pkey_st EVP_PKEY;
    typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
    typedef struct evp_md_st EVP_MD;
    typedef struct evp_md_ctx_st EVP_MD_CTX;
    
    BIO *BIO_new_mem_buf(const void *buf, int len);
    EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x, void *cb, void *u);
    void BIO_free(BIO *a);
    void EVP_PKEY_free(EVP_PKEY *pkey);
    
    EVP_MD_CTX *EVP_MD_CTX_new(void);
    void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
    const EVP_MD *EVP_sha256(void);
    
    int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                              const EVP_MD *type, void *e, EVP_PKEY *pkey);
    int EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
    int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen);
]]

local crypto = ffi.load("crypto")

-- ============================================================
-- Helper Functions
-- ============================================================

local function send_error(status, message)
    ngx.status = status
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({ error = message }))
    return ngx.exit(status)
end

local function base64url_decode(input)
    local remainder = #input % 4
    if remainder > 0 then
        input = input .. string.rep("=", 4 - remainder)
    end
    input = input:gsub("-", "+"):gsub("_", "/")
    return ngx.decode_base64(input)
end

-- ============================================================
-- ASN.1 Encoding for RSA Public Key
-- ============================================================

local function encode_length(len)
    if len < 128 then
        return string.char(len)
    elseif len < 256 then
        return string.char(0x81, len)
    else
        return string.char(0x82, math.floor(len / 256), len % 256)
    end
end

local function encode_integer(bytes)
    -- Add leading zero if high bit is set (to ensure positive number)
    if string.byte(bytes, 1) > 127 then
        bytes = string.char(0) .. bytes
    end
    return string.char(0x02) .. encode_length(#bytes) .. bytes
end

-- Convert JWK RSA key to PEM format
local function jwk_to_pem(jwk)
    local n = base64url_decode(jwk.n)
    local e = base64url_decode(jwk.e)
    
    if not n or not e then
        return nil, "Failed to decode modulus or exponent"
    end
    
    -- Build RSA public key structure
    local n_encoded = encode_integer(n)
    local e_encoded = encode_integer(e)
    local rsa_key = n_encoded .. e_encoded
    local rsa_sequence = string.char(0x30) .. encode_length(#rsa_key) .. rsa_key
    
    -- RSA algorithm identifier OID: 1.2.840.113549.1.1.1
    local algorithm_id = string.char(
        0x30, 0x0D,
        0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
        0x05, 0x00
    )
    
    -- SubjectPublicKeyInfo structure
    local bit_string = string.char(0x03) .. encode_length(#rsa_sequence + 1) .. string.char(0x00) .. rsa_sequence
    local spki = algorithm_id .. bit_string
    local der = string.char(0x30) .. encode_length(#spki) .. spki
    
    -- Convert to PEM format
    local b64 = ngx.encode_base64(der)
    local pem = "-----BEGIN PUBLIC KEY-----\n"
    for i = 1, #b64, 64 do
        pem = pem .. string.sub(b64, i, i + 63) .. "\n"
    end
    pem = pem .. "-----END PUBLIC KEY-----"
    
    return pem
end

-- ============================================================
-- RS256 Signature Verification using OpenSSL
-- ============================================================

local function verify_rs256(header_b64, payload_b64, signature_b64, pem_key)
    local signing_input = header_b64 .. "." .. payload_b64
    local signature = base64url_decode(signature_b64)
    
    if not signature then
        return false, "Invalid signature encoding"
    end
    
    -- Create BIO from PEM key
    local bio = crypto.BIO_new_mem_buf(pem_key, #pem_key)
    if bio == nil then
        return false, "Failed to create BIO"
    end
    
    -- Read public key from BIO
    local pkey = crypto.PEM_read_bio_PUBKEY(bio, nil, nil, nil)
    crypto.BIO_free(bio)
    
    if pkey == nil then
        return false, "Failed to load public key"
    end
    
    -- Create message digest context
    local md_ctx = crypto.EVP_MD_CTX_new()
    if md_ctx == nil then
        crypto.EVP_PKEY_free(pkey)
        return false, "Failed to create MD context"
    end
    
    -- Initialize verification
    local ret = crypto.EVP_DigestVerifyInit(md_ctx, nil, crypto.EVP_sha256(), nil, pkey)
    if ret ~= 1 then
        crypto.EVP_MD_CTX_free(md_ctx)
        crypto.EVP_PKEY_free(pkey)
        return false, "Failed to init verification"
    end
    
    -- Update with signing input
    ret = crypto.EVP_DigestVerifyUpdate(md_ctx, signing_input, #signing_input)
    if ret ~= 1 then
        crypto.EVP_MD_CTX_free(md_ctx)
        crypto.EVP_PKEY_free(pkey)
        return false, "Failed to update verification"
    end
    
    -- Verify signature
    ret = crypto.EVP_DigestVerifyFinal(md_ctx, signature, #signature)
    
    -- Cleanup
    crypto.EVP_MD_CTX_free(md_ctx)
    crypto.EVP_PKEY_free(pkey)
    
    return ret == 1
end

-- ============================================================
-- JWKS Fetching with Cache and Key Rotation Support
-- ============================================================

local function fetch_jwks(force_refresh)
    -- Check cache first (unless force refresh)
    if not force_refresh and jwks_cache then
        local cached = jwks_cache:get("jwks")
        if cached then
            local ok, jwks = pcall(cjson.decode, cached)
            if ok then
                return jwks
            end
        end
    end

    -- Fetch from Keycloak
    local httpc = http.new()
    httpc:set_timeout(5000)

    local res, err = httpc:request_uri(JWKS_URL, {
        method = "GET",
        ssl_verify = false,
    })

    if not res then
        ngx.log(ngx.ERR, "JWKS fetch failed: ", err)
        return nil, "Failed to fetch JWKS: " .. (err or "unknown")
    end

    if res.status ~= 200 then
        ngx.log(ngx.ERR, "JWKS endpoint returned: ", res.status)
        return nil, "JWKS endpoint returned: " .. res.status
    end

    local ok, jwks = pcall(cjson.decode, res.body)
    if not ok then
        return nil, "Invalid JWKS JSON"
    end

    -- Cache the JWKS
    if jwks_cache then
        jwks_cache:set("jwks", res.body, JWKS_CACHE_TTL)
    end

    return jwks
end

-- ============================================================
-- Find Key by KID
-- ============================================================

local function find_key_by_kid(jwks, kid)
    if not jwks or not jwks.keys then
        return nil
    end

    -- First try exact kid match for signing keys
    for _, key in ipairs(jwks.keys) do
        if key.kid == kid and key.use == "sig" then
            return key
        end
    end

    -- Fallback: first RS256 signing key if no kid provided
    if not kid then
        for _, key in ipairs(jwks.keys) do
            if key.kty == "RSA" and key.use == "sig" and (key.alg == "RS256" or not key.alg) then
                return key
            end
        end
    end

    return nil
end

-- ============================================================
-- Main Validation Logic
-- ============================================================

-- Bypass JWT validation for auth flow endpoints
local uri = ngx.var.uri
local bypass_paths = {
    ["/refresh"] = true,   -- Refresh token is in body, not JWT
    ["/login"] = true,     -- Redirects to Keycloak
    ["/logout"] = true,    -- Redirects to Keycloak logout
    ["/callback"] = true,  -- OAuth callback from Keycloak
}
if bypass_paths[uri] then
    return  -- Allow through without JWT
end

-- 1. Check Authorization header
local auth_header = ngx.var.http_authorization
if not auth_header then
    return send_error(401, "Missing Authorization header")
end

local _, _, token = string.find(auth_header, "Bearer%s+(.+)")
if not token then
    return send_error(401, "Invalid Authorization format")
end

-- 2. Split token into parts
local parts = {}
for part in string.gmatch(token, "[^%.]+") do
    table.insert(parts, part)
end

if #parts ~= 3 then
    return send_error(401, "Malformed token")
end

local header_b64, payload_b64, signature_b64 = parts[1], parts[2], parts[3]

-- 3. Decode and parse header to get algorithm and kid
local header_json = base64url_decode(header_b64)
if not header_json then
    return send_error(401, "Invalid token header")
end

local ok, header = pcall(cjson.decode, header_json)
if not ok then
    return send_error(401, "Invalid header JSON")
end

-- 4. Security: Only allow RS256 algorithm (prevents algorithm confusion attacks)
if header.alg ~= "RS256" then
    return send_error(401, "Unsupported algorithm: " .. (header.alg or "none"))
end

-- 5. Decode and parse payload
local payload_json = base64url_decode(payload_b64)
if not payload_json then
    return send_error(401, "Invalid token payload")
end

local ok, payload = pcall(cjson.decode, payload_json)
if not ok then
    return send_error(401, "Invalid payload JSON")
end

-- 6. Fetch JWKS and find matching key
local jwks, err = fetch_jwks(false)
if not jwks then
    return send_error(503, "Auth service unavailable")
end

local jwk = find_key_by_kid(jwks, header.kid)

-- 7. Handle key rotation: if kid not found, force refresh JWKS and retry
if not jwk and header.kid then
    ngx.log(ngx.WARN, "Key not found for kid: ", header.kid, ", refreshing JWKS")
    jwks, err = fetch_jwks(true)
    if jwks then
        jwk = find_key_by_kid(jwks, header.kid)
    end
end

if not jwk then
    return send_error(401, "No matching key found")
end

-- 8. Convert JWK to PEM format
local pem_key, err = jwk_to_pem(jwk)
if not pem_key then
    ngx.log(ngx.ERR, "JWK to PEM conversion failed: ", err)
    return send_error(500, "Key conversion failed")
end

-- 9. VERIFY RS256 SIGNATURE (This is the real security)
local verified, err = verify_rs256(header_b64, payload_b64, signature_b64, pem_key)
if not verified then
    ngx.log(ngx.WARN, "Signature verification failed: ", err or "invalid")
    return send_error(401, "Invalid token signature")
end

-- 10. Validate expiry (exp claim)
if payload.exp and payload.exp < ngx.time() then
    return send_error(401, "Token expired")
end

-- 11. Validate not-before (nbf claim)
if payload.nbf and payload.nbf > ngx.time() then
    return send_error(401, "Token not yet valid")
end

-- 12. Validate issuer (iss claim)
if not EXPECTED_ISSUERS[payload.iss] then
    ngx.log(ngx.WARN, "Invalid issuer: ", payload.iss)
    return send_error(401, "Invalid issuer")
end

-- 13. Validate audience (aud claim) if configured
if EXPECTED_AUD then
    local aud = payload.aud
    local aud_valid = false
    
    if type(aud) == "string" then
        aud_valid = (aud == EXPECTED_AUD)
    elseif type(aud) == "table" then
        for _, a in ipairs(aud) do
            if a == EXPECTED_AUD then
                aud_valid = true
                break
            end
        end
    end
    
    if not aud_valid then
        return send_error(401, "Invalid audience")
    end
end

-- 14. Forward verified user claims to backend via headers
ngx.req.set_header("X-User-ID", payload.sub or "")
ngx.req.set_header("X-User-Email", payload.email or "")
ngx.req.set_header("X-User-Preferred-Username", payload.preferred_username or "")
ngx.req.set_header("X-User-Roles", payload.realm_access and cjson.encode(payload.realm_access.roles) or "[]")
ngx.req.set_header("X-Token-Verified", "true")
ngx.req.set_header("X-Token-Issuer", payload.iss or "")

-- Success - request continues to backend
return
