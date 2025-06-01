-- kong/plugins/jwt-blacklist-jti/handler.lua

local redis = require "resty.redis"
local cjson = require "cjson.safe"

local plugin = {
  PRIORITY = 800,
  VERSION = "0.1.0",
}

-- base64url デコード関数
local function decode_base64url(input)
  if not input then return nil end
  input = input:gsub("-", "+"):gsub("_", "/")
  local padding = 4 - (#input % 4)
  if padding < 4 then
    input = input .. string.rep("=", padding)
  end
  return ngx.decode_base64(input)
end

-- JWT の jti を取得するヘルパー
local function get_jti_from_jwt(jwt_string)
  if not jwt_string then
    kong.log.warn("JWT string is nil")
    return nil
  end
  kong.log.debug("Raw JWT: ", jwt_string)
  local _, _, payload_b64 = jwt_string:find("^[^%.]+%.([^%.]+)%.[^%.]+$")
  if not payload_b64 then
    kong.log.warn("Invalid JWT format: could not find payload")
    return nil
  end
  kong.log.debug("Encoded payload: ", payload_b64)
  local decoded_payload_str = decode_base64url(payload_b64)
  if not decoded_payload_str then
    kong.log.warn("Failed to decode base64url payload")
    return nil
  end
  kong.log.debug("Decoded payload string: ", decoded_payload_str)
  local success, payload = pcall(cjson.decode, decoded_payload_str)
  if not success or type(payload) ~= "table" then
    kong.log.warn("Failed to decode JSON payload: ", payload)
    return nil
  end
  kong.log.debug("Parsed payload table: ", cjson.encode(payload))
  kong.log.debug("Extracted JTI: ", payload.jti)
  return payload.jti
end

-- メイン関数
function plugin:access(conf)

  if not conf then
    kong.log.err("Plugin configuration ('conf' object) is nil")
    return kong.response.exit(500, { message = "Plugin configuration object is nil" })
  end

  local auth_header = kong.request.get_header("Authorization")
  local jwt_token
  if auth_header and auth_header:lower():sub(1, 7) == "bearer " then
    jwt_token = auth_header:sub(8)
  else
    kong.log.warn("Missing or malformed Authorization header")
    return kong.response.exit(401, { message = "Unauthorized: Missing Bearer token" })
  end
  if not jwt_token then
    kong.log.warn("JWT token is missing after extraction")
    return kong.response.exit(401, { message = "Unauthorized: JWT token missing" })
  end
  local jti = get_jti_from_jwt(jwt_token)
  if not jti then
    kong.log.warn("Could not extract JTI from JWT")
    return kong.response.exit(401, { message = "Unauthorized: Invalid or malformed JWT" })
  end

  local red = redis:new()
  red:set_timeout(conf.redis_timeout)

  local ok, err = red:connect(conf.redis_host, conf.redis_port)
  if not ok then
    kong.log.err("Failed to connect to Redis: ", err)
    return kong.response.exit(500, { message = "Internal Server Error: Redis connection failed" })
  end

  if conf.redis_password and conf.redis_password ~= "" then
    local res, err_auth = red:auth(conf.redis_password)
    if not res then
      kong.log.err("Failed to authenticate to Redis: ", err_auth)
      red:close()
      return kong.response.exit(500, { message = "Internal Server Error: Redis authentication failed" })
    end
  end

  local redis_key = conf.redis_blacklist_prefix .. jti
  local res, err_get = red:get(redis_key)

  if err_get then
    kong.log.err("Failed to get value from Redis: ", err_get)
    red:set_keepalive(0)
    red:close()
    return kong.response.exit(500, { message = "Internal Server Error: Failed to query Redis blacklist" })
  end

  red:set_keepalive(10000, conf.redis_pool_size)

  if res and res ~= ngx.null then
    kong.log.info("Token revoked. JTI: ", jti)
    return kong.response.exit(401, { message = "Unauthorized: Token revoked" })
  end

  kong.log.debug("Token accepted. JTI not blacklisted: ", jti)
end

return plugin
