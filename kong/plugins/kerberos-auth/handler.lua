-- kerberos-auth: SPNEGO/Kerberos authentication for Kong.
--
-- access()        validates the client's Negotiate token and maps the principal
--                 onto a Kong consumer
-- header_filter() returns the mutual authentication token when the client
--                 asked for one
-- configure()     warms credentials and surfaces keytab problems at config
--                 time rather than on the first request

local gss       = require "kong.plugins.kerberos-auth.gssapi.ffi"
local acceptor  = require "kong.plugins.kerberos-auth.gssapi.acceptor"
local initiator = require "kong.plugins.kerberos-auth.gssapi.initiator"
local negotiate = require "kong.plugins.kerberos-auth.negotiate"
local consumers = require "kong.plugins.kerberos-auth.consumer"

local sha256 = require "resty.sha256"
local to_hex = require("resty.string").to_hex

local kong = kong
local ngx = ngx

local KerberosAuthHandler = {
  -- Below key-auth (1250) and ldap-auth (1200) so it chains predictably, and
  -- comfortably above acl (950) and the rate limiting plugins.
  PRIORITY = 1000,
  VERSION  = "0.1.0",
}


---------------------------------------------------------------------------
-- Environment
---------------------------------------------------------------------------

-- The krb5 library reads these at call time. nginx workers start with a
-- scrubbed environment, so they have to be set from Lua.
local applied_env = {}


local function apply_env(name, value)
  if value == nil or value == "" then
    return
  end
  if applied_env[name] == value then
    return
  end
  gss.setenv(name, value)
  applied_env[name] = value
end


local function ensure_environment(conf)
  apply_env("KRB5_CONFIG", conf.krb5_config)

  if conf.replay_cache == "none" then
    -- MIT's default acceptor replay cache writes a file per request into
    -- /var/tmp, which is both a hot spot and a container footgun. Kong sits in
    -- front of the real application, which is where replay protection belongs.
    apply_env("KRB5RCACHETYPE", "none")
    apply_env("KRB5RCACHENAME", "none:")
  end
end


---------------------------------------------------------------------------
-- Option shaping
---------------------------------------------------------------------------

local function acceptor_opts(conf)
  return {
    library           = conf.gssapi_library,
    keytab            = conf.keytab,
    service_principal = conf.service_principal,
    want_delegated    = conf.upstream.enabled and conf.upstream.use_delegated_credential,
  }
end


local function token_cache_key(token)
  local digest = sha256:new()
  digest:update(token)
  return "kerberos-auth:token:" .. to_hex(digest:final())
end


---------------------------------------------------------------------------
-- Responses
---------------------------------------------------------------------------

-- Falls back to the anonymous consumer when one is configured, which is how
-- Kong auth plugins chain. Returns true when the request may continue.
local function try_anonymous(conf)
  if not conf.anonymous or conf.anonymous == "" then
    return false
  end

  local consumer, err = consumers.find_anonymous(conf.anonymous)
  if err then
    kong.log.err("kerberos-auth: failed to load anonymous consumer '",
                 conf.anonymous, "': ", err)
    return kong.response.exit(500, { message = "An unexpected error occurred" })
  end

  if not consumer then
    kong.log.err("kerberos-auth: anonymous consumer '", conf.anonymous, "' not found")
    return kong.response.exit(500, { message = "An unexpected error occurred" })
  end

  consumers.set_authenticated(conf, consumer, nil, true)
  return true
end


local function unauthorized(conf, message, response_token)
  if try_anonymous(conf) then
    return
  end

  local headers
  if conf.challenge_on_missing or response_token then
    headers = { ["WWW-Authenticate"] = negotiate.challenge(conf.scheme, response_token) }
  end

  return kong.response.exit(401, { message = message or "Unauthorized" }, headers)
end


-- Authorisation failures are deliberate decisions about a caller we did
-- successfully authenticate, so they are never downgraded to the anonymous
-- consumer. Only authentication failures fall back, which is what
-- config.anonymous means in Kong's other auth plugins. Use
-- consumer.on_missing = "anonymous" to let unmapped principals through.
local function forbidden(conf, message)
  return kong.response.exit(403, { message = message or "Forbidden" })
end


---------------------------------------------------------------------------
-- Authorisation filters
---------------------------------------------------------------------------

-- Returns nil when the principal passes, or a log-safe reason when it does not.
local function rejected_reason(conf, principal, realm)
  if conf.realm and conf.realm ~= "" and realm ~= conf.realm then
    return "principal is from realm '" .. tostring(realm) ..
           "', expected '" .. conf.realm .. "'"
  end

  local re_find = ngx.re.find

  if negotiate.matches_any(principal, conf.denied_principals, re_find) then
    return "principal is on the deny list"
  end

  if conf.allowed_principals and #conf.allowed_principals > 0
     and not negotiate.matches_any(principal, conf.allowed_principals, re_find) then
    return "principal is not on the allow list"
  end

  return nil
end


---------------------------------------------------------------------------
-- Consumer mapping
---------------------------------------------------------------------------

-- Returns true when the request may continue.
local function map_consumer(conf, principal)
  if not conf.consumer.enabled then
    consumers.set_authenticated(conf, nil, principal, false)
    return true
  end

  local lookup_key, terr = consumers.lookup_key(conf, principal)
  if not lookup_key then
    kong.log.err("kerberos-auth: ", terr, " for principal '", principal, "'")
    kong.response.exit(500, { message = "An unexpected error occurred" })
    return false
  end

  local consumer, err = consumers.find(lookup_key, conf.consumer.by,
                                       conf.consumer.cache_ttl)
  if err then
    kong.log.err("kerberos-auth: consumer lookup failed for '", lookup_key, "': ", err)
    kong.response.exit(500, { message = "An unexpected error occurred" })
    return false
  end

  if consumer then
    consumers.set_authenticated(conf, consumer, principal, false)
    return true
  end

  local on_missing = conf.consumer.on_missing

  if on_missing == "allow" then
    kong.log.info("kerberos-auth: no consumer matches '", lookup_key,
                  "', proxying without one")
    consumers.set_authenticated(conf, nil, principal, false)
    return true
  end

  if on_missing == "anonymous" then
    if try_anonymous(conf) then
      return true
    end
    return false
  end

  kong.log.info("kerberos-auth: authenticated '", principal,
                "' but no consumer matches '", lookup_key, "'")
  forbidden(conf, "Authenticated principal is not a known consumer")
  return false
end


---------------------------------------------------------------------------
-- Upstream Kerberos leg
---------------------------------------------------------------------------

local function upstream_target(conf)
  local configured = conf.upstream.service_principal
  if configured and configured ~= "" then
    return configured
  end

  local service = kong.router.get_service()
  local host = service and service.host

  if not host then
    local balancer_data = ngx.ctx.balancer_data
    host = balancer_data and balancer_data.host
  end

  if not host then
    return nil, "could not determine the upstream host; set " ..
                "config.upstream.service_principal"
  end

  return "HTTP@" .. host
end


local function authenticate_upstream(conf, result)
  local up = conf.upstream

  local target, terr = upstream_target(conf)
  if not target then
    kong.log.err("kerberos-auth: ", terr)
    return
  end

  local delegated
  if up.use_delegated_credential and result and result.delegated then
    delegated = result.delegated
    kong.log.debug("kerberos-auth: upstream leg using delegated credential of \x27",
                   tostring(result.delegated_name), "\x27")
  end

  if up.use_delegated_credential and not delegated then
    kong.log.info("kerberos-auth: no delegated credential available, ",
                  "authenticating upstream as \x27", tostring(up.client_principal), "\x27")
  end

  local token, err = initiator.initiate({
    library          = conf.gssapi_library,
    keytab           = (up.keytab ~= nil and up.keytab ~= "") and up.keytab or conf.keytab,
    client_principal = up.client_principal,
    mutual           = up.mutual,
    mechanism        = up.mechanism,
    delegated        = delegated,
  }, target)

  if not token then
    kong.log.err("kerberos-auth: upstream authentication failed: ", err)
    return
  end

  kong.service.request.set_header(up.header_name, "Negotiate " .. ngx.encode_base64(token))
end


---------------------------------------------------------------------------
-- Phases
---------------------------------------------------------------------------

-- Called whenever the plugin configuration changes. Warming here turns a bad
-- keytab into a startup log line instead of a surprise 401 storm.
function KerberosAuthHandler:configure(configs)
  if not configs then
    return
  end

  for _, conf in ipairs(configs) do
    ensure_environment(conf)

    local opts = acceptor_opts(conf)
    local principal, err = acceptor.describe_credential(opts)

    if principal then
      kong.log.info("kerberos-auth: acceptor credential ready as '", principal,
                    "' from keytab '", conf.keytab, "'")
    else
      kong.log.err("kerberos-auth: acceptor credential unavailable: ", err)
    end

    if conf.upstream.enabled and conf.upstream.client_principal then
      local _, _, ierr = initiator.acquire_credential({
        library          = conf.gssapi_library,
        keytab           = (conf.upstream.keytab ~= nil and conf.upstream.keytab ~= "")
                           and conf.upstream.keytab or conf.keytab,
        client_principal = conf.upstream.client_principal,
      })
      if ierr then
        kong.log.err("kerberos-auth: initiator credential unavailable: ", ierr)
      else
        kong.log.info("kerberos-auth: initiator credential ready as '",
                      conf.upstream.client_principal, "'")
      end
    end
  end
end

-- Runs the GSS-API exchange, retrying once if the cached acceptor credential
-- turned out to be stale (rotated or expired keytab).
local function validate(opts, token)
  local result, err = acceptor.accept(opts, token)

  if not result and err and err.retryable then
    result, err = acceptor.accept(opts, token)
  end

  return result, err
end


function KerberosAuthHandler:access(conf)
  if not conf.run_on_preflight and kong.request.get_method() == "OPTIONS" then
    return
  end

  -- Another authentication plugin already identified the caller.
  if conf.anonymous and conf.anonymous ~= "" and kong.client.get_credential() then
    return
  end

  ensure_environment(conf)

  local header = kong.request.get_header(conf.header_name)
  local token, parse_err = negotiate.parse_header(header, conf.scheme)

  if not token then
    if parse_err == negotiate.ERR_SCHEME then
      return unauthorized(conf, "Unsupported authentication scheme")
    end
    if parse_err == negotiate.ERR_MISSING then
      return unauthorized(conf, "Unauthorized")
    end
    return unauthorized(conf, "Invalid Negotiate token")
  end

  local opts = acceptor_opts(conf)

  -- Memoising the validation is incompatible with delegation, which needs the
  -- live credential produced by the handshake.
  local use_cache = conf.cache.enabled and not opts.want_delegated

  local result, accept_err

  if use_cache then
    -- The callback caches successes only: returning an error from it makes
    -- mlcache propagate without storing, so a rejected token is re-validated.
    local principal, cache_err = kong.cache:get(token_cache_key(token),
                                                { ttl = conf.cache.ttl },
                                                function()
      local validated, verr = validate(opts, token)
      if not validated then
        accept_err = verr
        return nil, (verr and verr.message) or "authentication failed"
      end

      result = validated
      return validated.principal
    end)

    if principal and not result then
      result = { principal = principal, from_cache = true }
    elseif not principal and not accept_err then
      accept_err = { message = cache_err }
    end

  else
    result, accept_err = validate(opts, token)
  end

  if not result then
    kong.log.warn("kerberos-auth: token rejected: ",
                  (accept_err and accept_err.message) or "unknown error")
    return unauthorized(conf, "Invalid Negotiate token",
                        accept_err and accept_err.continue_needed
                        and accept_err.out_token or nil)
  end

  kong.log.debug("kerberos-auth: authenticated \x27", result.principal,
                 "\x27 (flags=", tostring(result.flags), ", delegated=",
                 tostring(result.delegated ~= nil), ")")

  local principal = result.principal
  local _, _, realm = negotiate.identity(principal, conf)

  local reason = rejected_reason(conf, principal, realm)
  if reason then
    kong.log.info("kerberos-auth: rejected '", principal, "': ", reason)
    acceptor.release_delegated(opts, result)
    return forbidden(conf, "Forbidden")
  end

  consumers.set_principal_headers(conf, principal)

  if not map_consumer(conf, principal) then
    acceptor.release_delegated(opts, result)
    return
  end

  if conf.upstream.enabled then
    authenticate_upstream(conf, result)
  end

  acceptor.release_delegated(opts, result)

  if conf.hide_credentials then
    kong.service.request.clear_header(conf.header_name)
  end

  -- RFC 4559: when the client asked for mutual authentication it expects the
  -- acceptor's token back on the successful response.
  if result.mutual and result.out_token then
    kong.ctx.plugin.mutual_token = result.out_token
  end
end


function KerberosAuthHandler:header_filter(conf)
  local token = kong.ctx.plugin.mutual_token
  if token then
    kong.response.set_header("WWW-Authenticate", negotiate.challenge(conf.scheme, token))
  end
end

return KerberosAuthHandler
