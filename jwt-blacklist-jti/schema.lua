-- kong/plugins/jwt-blacklist-jti/schema.lua

return {
  name = "jwt-blacklist-jti",
  fields = {
    { config = {
        type = "record",
        fields = {
          { redis_host = { type = "string", default = "127.0.0.1" } },
          { redis_port = { type = "number", default = 6379 } },
          { redis_password = { type = "string", default = nil, required = false } },
          { redis_timeout = { type = "number", default = 2000 } },
          { redis_blacklist_prefix = { type = "string", default = "blacklist:jti:" } },
          { redis_pool_size = { type = "number", default = 100 } },
        },
      },
    },
  },
}
