FROM openresty/openresty:alpine-fat

# Install dependencies first
RUN opm get ledgetech/lua-resty-http
RUN opm get jkeys089/lua-resty-hmac  
RUN opm get openresty/lua-resty-string
RUN opm get cdbattags/lua-resty-jwt
RUN opm get openresty/lua-resty-limit-traffic