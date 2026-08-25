-- Maps an authenticated Kerberos principal onto a Kong consumer and publishes
-- the standard authentication context, so that ACL, rate limiting and logging
-- plugins behave exactly as they do behind key-auth or ldap-auth.

local constants = require "kong.constants"
local negotiate = require "kong.plugins.kerberos-auth.negotiate"

local kong = kong

local HEADERS = constants.HEADERS
local AUTHENTICATED_USERID = "X-Authenticated-Userid"


local _M = {}


local function load_consumer_by_username(username)
  return kong.db.consumers:select_by_username(username)
end


local function load_consumer_by_custom_id(custom_id)
  return kong.db.consumers:select_by_custom_id(custom_id)
end


-- Looks a consumer up through Kong's cache.
--
-- The `username` path uses the DAO cache key so Kong's own entity invalidation
-- events apply. `custom_id` has no cache key on the consumers schema, so it
-- falls back to a plugin scoped key with a bounded TTL: updates to a consumer's
-- custom_id take up to `cache_ttl` seconds to be picked up.
function _M.find(lookup_key, by, cache_ttl)
  if by == "custom_id" then
    local cache_key = "kerberos-auth:custom_id:" .. lookup_key
    return kong.cache:get(cache_key, { ttl = cache_ttl, neg_ttl = cache_ttl },
                          load_consumer_by_custom_id, lookup_key)
  end

  local cache_key = kong.db.consumers:cache_key(lookup_key)
  return kong.cache:get(cache_key, nil, load_consumer_by_username, lookup_key)
end


-- Resolves `config.anonymous`, which may be a consumer id or a username. This
-- is the same lookup Kong's own auth plugins perform, so an anonymous consumer
-- configured for key-auth or ldap-auth can be reused here verbatim.
function _M.find_anonymous(id_or_username)
  local cache_key = kong.db.consumers:cache_key(id_or_username)
  return kong.cache:get(cache_key, nil, kong.client.load_consumer,
                        id_or_username, true)
end


-- Builds the consumer lookup key from the configured template.
function _M.lookup_key(conf, principal)
  local identity, user, realm = negotiate.identity(principal, conf)

  return negotiate.render_template(conf.consumer.template, {
    identity  = identity,
    principal = principal,
    user      = user,
    realm     = realm,
  })
end


-- Publishes the authentication result. `consumer` may be nil when
-- `consumer.on_missing = "allow"`, in which case the credential alone is set so
-- log plugins still record who called.
function _M.set_authenticated(conf, consumer, principal, anonymous)
  local set_header = kong.service.request.set_header
  local clear_header = kong.service.request.clear_header

  local credential = principal and {
    id          = principal,
    consumer_id = consumer and consumer.id or nil,
    principal   = principal,
  } or nil

  kong.client.authenticate(consumer, credential)

  if consumer then
    set_header(HEADERS.CONSUMER_ID, consumer.id)

    if consumer.custom_id and consumer.custom_id ~= "" then
      set_header(HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
    else
      clear_header(HEADERS.CONSUMER_CUSTOM_ID)
    end

    if consumer.username and consumer.username ~= "" then
      set_header(HEADERS.CONSUMER_USERNAME, consumer.username)
    else
      clear_header(HEADERS.CONSUMER_USERNAME)
    end
  else
    clear_header(HEADERS.CONSUMER_ID)
    clear_header(HEADERS.CONSUMER_CUSTOM_ID)
    clear_header(HEADERS.CONSUMER_USERNAME)
  end

  if anonymous then
    set_header(HEADERS.ANONYMOUS, true)
  else
    clear_header(HEADERS.ANONYMOUS)
  end

  if credential then
    set_header(HEADERS.CREDENTIAL_IDENTIFIER, credential.id)
  else
    clear_header(HEADERS.CREDENTIAL_IDENTIFIER)
  end

  if conf.set_authenticated_userid and principal then
    set_header(AUTHENTICATED_USERID, principal)
  end
end


-- Sets the informational Kerberos headers. Always carries the untouched
-- principal, independent of how the consumer lookup key was derived.
function _M.set_principal_headers(conf, principal)
  local set_header = kong.service.request.set_header
  local _, realm = negotiate.split_principal(principal)

  if conf.principal_header and conf.principal_header ~= "" then
    set_header(conf.principal_header, principal)
  end

  if conf.realm_header and conf.realm_header ~= "" and realm then
    set_header(conf.realm_header, realm)
  end
end


return _M
