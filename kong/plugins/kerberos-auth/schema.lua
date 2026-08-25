local typedefs = require "kong.db.schema.typedefs"

local PLUGIN_NAME = "kerberos-auth"


local function non_empty_string(value)
  if value ~= nil and value ~= "" then
    return true
  end
  return nil, "must not be empty"
end


return {
  name = PLUGIN_NAME,
  fields = {
    { protocols = typedefs.protocols_http },
    -- Authentication plugins run before a consumer is known, so they cannot be
    -- scoped to one.
    { consumer = typedefs.no_consumer },
    { config = {
        type = "record",
        fields = {

          ------------------------------------------------------------------
          -- Kerberos identity
          ------------------------------------------------------------------
          { keytab = {
              description = "Path to the keytab holding the service key Kong accepts tickets for.",
              type = "string",
              required = true,
              default = "/etc/krb5.keytab",
              custom_validator = non_empty_string,
          } },
          { service_principal = {
              description = "Service principal to accept as, e.g. `HTTP@kong.example.com` or " ..
                            "`HTTP/kong.example.com@EXAMPLE.COM`. When unset, any principal " ..
                            "present in the keytab is accepted.",
              type = "string",
          } },
          { krb5_config = {
              description = "Path to krb5.conf. Defaults to the system location.",
              type = "string",
          } },
          { gssapi_library = {
              description = "Shared library implementing the GSS-API.",
              type = "string",
              required = true,
              default = "libgssapi_krb5.so.2",
          } },
          { replay_cache = {
              description = "MIT replay cache mode. `none` disables the per-request rcache " ..
                            "file I/O, which is the right trade-off behind a gateway; " ..
                            "`default` keeps the library's own replay protection.",
              type = "string",
              required = true,
              default = "none",
              one_of = { "none", "default" },
          } },

          ------------------------------------------------------------------
          -- Request handling
          ------------------------------------------------------------------
          { header_name = {
              description = "Request header carrying the Negotiate token.",
              type = "string",
              required = true,
              default = "Authorization",
              custom_validator = non_empty_string,
          } },
          { scheme = {
              description = "Authentication scheme expected in the header.",
              type = "string",
              required = true,
              default = "Negotiate",
              custom_validator = non_empty_string,
          } },
          { challenge_on_missing = {
              description = "Answer requests without a token with 401 and a " ..
                            "`WWW-Authenticate` challenge, which is what starts the exchange.",
              type = "boolean",
              required = true,
              default = true,
          } },
          { hide_credentials = {
              description = "Strip the Negotiate header before proxying upstream.",
              type = "boolean",
              required = true,
              default = false,
          } },
          { run_on_preflight = {
              description = "Also authenticate CORS preflight (OPTIONS) requests.",
              type = "boolean",
              required = true,
              default = true,
          } },

          ------------------------------------------------------------------
          -- Principal shaping and authorisation
          ------------------------------------------------------------------
          { realm = {
              description = "Only accept principals from this realm.",
              type = "string",
          } },
          { allowed_principals = {
              description = "Allow list of principals. Entries starting with `~` are treated " ..
                            "as PCRE patterns. When set, everything else is rejected.",
              type = "array",
              elements = { type = "string" },
          } },
          { denied_principals = {
              description = "Deny list of principals, evaluated before the allow list. " ..
                            "Entries starting with `~` are treated as PCRE patterns.",
              type = "array",
              elements = { type = "string" },
          } },
          { strip_realm = {
              description = "Drop `@REALM` when deriving the identity used for consumer lookup.",
              type = "boolean",
              required = true,
              default = true,
          } },
          { principal_lowercase = {
              description = "Lowercase the derived identity. Useful with Active Directory.",
              type = "boolean",
              required = true,
              default = false,
          } },

          ------------------------------------------------------------------
          -- Consumer mapping
          ------------------------------------------------------------------
          { consumer = {
              type = "record",
              required = true,
              fields = {
                { enabled = {
                    description = "Map the authenticated principal onto a Kong consumer so that " ..
                                  "ACL, rate limiting and logging plugins see it.",
                    type = "boolean",
                    required = true,
                    default = true,
                } },
                { by = {
                    description = "Consumer field to match the rendered lookup key against.",
                    type = "string",
                    required = true,
                    default = "username",
                    one_of = { "username", "custom_id" },
                } },
                { template = {
                    description = "Lookup key template. Placeholders: `${identity}` (principal " ..
                                  "after `strip_realm`/`principal_lowercase`), `${principal}` " ..
                                  "(full principal), `${user}`, `${realm}`.",
                    type = "string",
                    required = true,
                    default = "${identity}",
                    custom_validator = non_empty_string,
                } },
                { on_missing = {
                    description = "Behaviour when no consumer matches: `deny` returns 403, " ..
                                  "`allow` proxies without a consumer, `anonymous` falls back " ..
                                  "to `config.anonymous`.",
                    type = "string",
                    required = true,
                    default = "deny",
                    one_of = { "deny", "allow", "anonymous" },
                } },
                { cache_ttl = {
                    description = "TTL in seconds for negative and `custom_id` consumer lookups.",
                    type = "number",
                    required = true,
                    default = 60,
                    between = { 0, 86400 },
                } },
              },
          } },
          { anonymous = {
              description = "Consumer id or username used when `consumer.on_missing` is " ..
                            "`anonymous`, or to chain this plugin with another auth plugin.",
              type = "string",
          } },

          ------------------------------------------------------------------
          -- Upstream headers
          ------------------------------------------------------------------
          { principal_header = {
              description = "Header carrying the full authenticated principal upstream. " ..
                            "Set to `null` to disable.",
              type = "string",
              default = "X-Kerberos-Principal",
          } },
          { realm_header = {
              description = "Header carrying the authenticated realm upstream. " ..
                            "Set to `null` to disable.",
              type = "string",
              default = "X-Kerberos-Realm",
          } },
          { set_authenticated_userid = {
              description = "Set `X-Authenticated-Userid` and the authenticated credential so " ..
                            "log plugins record the principal.",
              type = "boolean",
              required = true,
              default = true,
          } },

          ------------------------------------------------------------------
          -- Token cache
          ------------------------------------------------------------------
          { cache = {
              type = "record",
              required = true,
              fields = {
                { enabled = {
                    description = "Memoise successful token validations. This accepts a replay " ..
                                  "of the same token for up to `ttl` seconds in exchange for " ..
                                  "skipping the handshake, so it is off by default.",
                    type = "boolean",
                    required = true,
                    default = false,
                } },
                { ttl = {
                    description = "Lifetime of a memoised validation, in seconds.",
                    type = "number",
                    required = true,
                    default = 60,
                    between = { 1, 3600 },
                } },
              },
          } },

          ------------------------------------------------------------------
          -- Upstream Kerberos (initiator)
          ------------------------------------------------------------------
          { upstream = {
              type = "record",
              required = true,
              fields = {
                { enabled = {
                    description = "Authenticate to a Kerberos protected upstream with a " ..
                                  "Negotiate header. Involves synchronous KDC round trips on " ..
                                  "cache misses, so it is off by default.",
                    type = "boolean",
                    required = true,
                    default = false,
                } },
                { service_principal = {
                    description = "Upstream service principal. Defaults to `HTTP@<upstream host>`.",
                    type = "string",
                } },
                { client_principal = {
                    description = "Principal Kong authenticates as when no delegated credential " ..
                                  "is available.",
                    type = "string",
                } },
                { keytab = {
                    description = "Keytab holding `client_principal`. Defaults to `config.keytab`.",
                    type = "string",
                } },
                { use_delegated_credential = {
                    description = "Reuse the caller's delegated credential when they sent one, " ..
                                  "so the upstream sees the original user.",
                    type = "boolean",
                    required = true,
                    default = true,
                } },
                { header_name = {
                    description = "Header used to carry the upstream Negotiate token.",
                    type = "string",
                    required = true,
                    default = "Authorization",
                    custom_validator = non_empty_string,
                } },
                { mechanism = {
                    description = "GSS mechanism for the upstream token. `auto` uses SPNEGO " ..
                                  "for Kong's own identity and raw Kerberos for a delegated " ..
                                  "credential, which is the only combination MIT honours " ..
                                  "without silently falling back to the default identity.",
                    type = "string",
                    required = true,
                    default = "auto",
                    one_of = { "auto", "spnego", "krb5" },
                } },
                { mutual = {
                    description = "Request mutual authentication from the upstream.",
                    type = "boolean",
                    required = true,
                    default = false,
                } },
              },
          } },
        },
    } },
  },

  entity_checks = {
    { custom_entity_check = {
        field_sources = { "config" },
        fn = function(entity)
          local config = entity.config
          if not config then
            return true
          end

          if config.consumer and config.consumer.on_missing == "anonymous"
             and (config.anonymous == nil or config.anonymous == "") then
            return nil, "config.anonymous is required when " ..
                        "config.consumer.on_missing is 'anonymous'"
          end

          local upstream = config.upstream
          if upstream and upstream.enabled
             and not upstream.use_delegated_credential
             and (upstream.client_principal == nil or upstream.client_principal == "") then
            return nil, "config.upstream.client_principal is required when " ..
                        "config.upstream.use_delegated_credential is false"
          end

          return true
        end,
    } },
  },
}
