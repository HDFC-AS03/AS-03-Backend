-- ============================================================
-- Enterprise JWT Validator with RS256 Signature Verification
-- Gateway: OpenResty | IdP: Keycloak | Algorithm: RS256
-- ============================================================

local http = require "resty.http"
local cjson = require "cjson"
local ffi = require "ffi"
local limit_req = require "resty.limit.req"

-- ============================================================
-- Configuration
-- ============================================================

local JWKS_URL = "http://keycloak:8080/realms/auth-realm/protocol/openid-connect/certs"

local EXPECTED_ISSUERS = {
    ["http://keycloak:8080/realms/auth-realm"] = true,
    ["http://localhost:8080/realms/auth-realm"] = true,
}

local EXPECTED_AUD = nil
local JWKS_CACHE_TTL = 300

local jwks_cache = ngx.shared.jwks_cache
local rate_store = "rate_limit_store"

-- ============================================================
-- Rate Limiter
-- ============================================================

local limiter, err = limit_req.new(rate_store, 10, 20)

if not limiter then
    ngx.log(ngx.ERR, "failed to create rate limiter: ", err)
end

-- ============================================================
-- OpenSSL FFI
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
-- ASN1 Encoding
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
    if string.byte(bytes, 1) > 127 then
        bytes = string.char(0) .. bytes
    end
    return string.char(0x02) .. encode_length(#bytes) .. bytes
end

local function jwk_to_pem(jwk)

    local n = base64url_decode(jwk.n)
    local e = base64url_decode(jwk.e)

    if not n or not e then
        return nil, "invalid jwk"
    end

    local n_encoded = encode_integer(n)
    local e_encoded = encode_integer(e)

    local rsa_key = n_encoded .. e_encoded
    local rsa_sequence = string.char(0x30) .. encode_length(#rsa_key) .. rsa_key

    local algorithm_id = string.char(
        0x30,0x0D,
        0x06,0x09,
        0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,
        0x05,0x00
    )

    local bit_string = string.char(0x03) .. encode_length(#rsa_sequence + 1) .. string.char(0x00) .. rsa_sequence

    local spki = algorithm_id .. bit_string
    local der = string.char(0x30) .. encode_length(#spki) .. spki

    local b64 = ngx.encode_base64(der)

    local pem = "-----BEGIN PUBLIC KEY-----\n"

    for i=1,#b64,64 do
        pem = pem .. string.sub(b64,i,i+63).."\n"
    end

    pem = pem .. "-----END PUBLIC KEY-----"

    return pem
end

-- ============================================================
-- RS256 Verification
-- ============================================================

local function verify_rs256(header_b64,payload_b64,signature_b64,pem)

    local signing_input = header_b64.."."..payload_b64
    local signature = base64url_decode(signature_b64)

    if not signature then
        return false
    end

    local bio = crypto.BIO_new_mem_buf(pem,#pem)
    if bio == nil then
        return false
    end

    local pkey = crypto.PEM_read_bio_PUBKEY(bio,nil,nil,nil)
    crypto.BIO_free(bio)

    if pkey == nil then
        return false
    end

    local ctx = crypto.EVP_MD_CTX_new()

    crypto.EVP_DigestVerifyInit(ctx,nil,crypto.EVP_sha256(),nil,pkey)
    crypto.EVP_DigestVerifyUpdate(ctx,signing_input,#signing_input)

    local ret = crypto.EVP_DigestVerifyFinal(ctx,signature,#signature)

    crypto.EVP_MD_CTX_free(ctx)
    crypto.EVP_PKEY_free(pkey)

    return ret == 1
end

-- ============================================================
-- JWKS Fetch
-- ============================================================

local function fetch_jwks(force)

    if not force and jwks_cache then
        local cached = jwks_cache:get("jwks")
        if cached then
            return cjson.decode(cached)
        end
    end

    local httpc = http.new()
    httpc:set_timeout(5000)

    local res = httpc:request_uri(JWKS_URL,{method="GET"})

    if not res or res.status ~= 200 then
        return nil
    end

    local jwks = cjson.decode(res.body)

    if jwks_cache then
        jwks_cache:set("jwks",res.body,JWKS_CACHE_TTL)
    end

    return jwks
end

local function find_key_by_kid(jwks,kid)

    if not jwks or not jwks.keys then
        return nil
    end

    for _,key in ipairs(jwks.keys) do
        if key.kid == kid and key.use=="sig" then
            return key
        end
    end

    return nil
end

-- ============================================================
-- Bypass Paths
-- ============================================================

local uri = ngx.var.uri

local bypass_paths = {
["/login"]=true,
["/logout"]=true,
["/callback"]=true,
["/refresh"]=true
}

if uri == "/refresh"
or uri == "/login"
or uri == "/logout"
or uri == "/callback" then
    return
end

-- ============================================================
-- Extract Token
-- ============================================================

local token

local auth = ngx.var.http_authorization

if auth then
    token = string.match(auth,"Bearer%s+(.+)")
end

if not token then
    token = ngx.var.cookie_access_token
end

if not token then
    return send_error(401,"Missing authentication")
end

-- ============================================================
-- Parse Token
-- ============================================================

local parts = {}

for part in string.gmatch(token,"[^%.]+") do
table.insert(parts,part)
end

if #parts ~= 3 then
return send_error(401,"Malformed token")
end

local header_b64 = parts[1]
local payload_b64 = parts[2]
local sig_b64 = parts[3]

local header = cjson.decode(base64url_decode(header_b64))

if header.alg ~= "RS256" then
return send_error(401,"Unsupported algorithm")
end

local payload = cjson.decode(base64url_decode(payload_b64))

-- ============================================================
-- JWKS Verification
-- ============================================================

local jwks = fetch_jwks(false)

if not jwks then
return send_error(503,"Auth unavailable")
end

local jwk = find_key_by_kid(jwks,header.kid)

if not jwk then
jwks = fetch_jwks(true)
jwk = find_key_by_kid(jwks,header.kid)
end

if not jwk then
return send_error(401,"Key not found")
end

local pem = jwk_to_pem(jwk)

if not verify_rs256(header_b64,payload_b64,sig_b64,pem) then
return send_error(401,"Invalid signature")
end

-- ============================================================
-- Claims Validation
-- ============================================================

local now = ngx.time()

if payload.exp and payload.exp < now then
return send_error(401,"Token expired")
end

if payload.nbf and payload.nbf > now then
return send_error(401,"Token not yet valid")
end

if not EXPECTED_ISSUERS[payload.iss] then
return send_error(401,"Invalid issuer")
end

-- ============================================================
-- Rate Limiting (after authentication)
-- ============================================================

if limiter then

local key = payload.sub or ngx.var.binary_remote_addr

local delay,err = limiter:incoming(key,true)

if not delay then
if err=="rejected" then
return send_error(429,"Too many requests")
end
end

if delay > 0 then
ngx.sleep(delay)
end

end

-- ============================================================
-- Forward Identity
-- ============================================================

ngx.req.set_header("X-User-ID",payload.sub or "")
ngx.req.set_header("X-User-Email",payload.email or "")
ngx.req.set_header("X-User-Preferred-Username",payload.preferred_username or "")
ngx.req.set_header("X-User-Roles",payload.realm_access and cjson.encode(payload.realm_access.roles) or "[]")
ngx.req.set_header("X-Token-Exp",tostring(payload.exp or 0))
ngx.req.set_header("X-Token-Verified","true")

return