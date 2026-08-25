-- HTTP "Negotiate" (RFC 4559) helpers and principal shaping.
--
-- Deliberately free of FFI and of Kong globals so it stays easy to reason
-- about and to exercise in isolation.

local ngx_decode_base64 = ngx and ngx.decode_base64
local ngx_encode_base64 = ngx and ngx.encode_base64

local lower = string.lower
local find = string.find
local sub = string.sub
local gsub = string.gsub
local match = string.match

local _M = {}


_M.ERR_MISSING     = "missing"
_M.ERR_SCHEME      = "scheme_mismatch"
_M.ERR_MALFORMED   = "malformed"
_M.ERR_EMPTY_TOKEN = "empty_token"


-- Extracts the raw (base64 decoded) token from an Authorization style header.
--
-- Returns token, nil on success or nil, <ERR_*> otherwise. Multiple header
-- values are tolerated: the first one carrying the right scheme wins, which is
-- what happens when a proxy in front of Kong appends its own credentials.
function _M.parse_header(value, scheme)
  if value == nil then
    return nil, _M.ERR_MISSING
  end

  local values = value
  if type(values) ~= "table" then
    values = { values }
  end

  local scheme_lower = lower(scheme or "Negotiate")
  local scheme_len = #scheme_lower
  local saw_other_scheme = false

  for _, candidate in ipairs(values) do
    if type(candidate) == "string" then
      local trimmed = match(candidate, "^%s*(.-)%s*$")

      if trimmed ~= "" then
        if lower(sub(trimmed, 1, scheme_len)) == scheme_lower then
          local separator = sub(trimmed, scheme_len + 1, scheme_len + 1)

          if separator == "" then
            return nil, _M.ERR_EMPTY_TOKEN
          end

          if separator == " " or separator == "\t" then
            local encoded = match(sub(trimmed, scheme_len + 1), "^%s*(%S+)%s*$")
            if not encoded then
              return nil, _M.ERR_EMPTY_TOKEN
            end

            local token = ngx_decode_base64(encoded)
            if not token or token == "" then
              return nil, _M.ERR_MALFORMED
            end

            return token
          end
        end

        saw_other_scheme = true
      end
    end
  end

  return nil, saw_other_scheme and _M.ERR_SCHEME or _M.ERR_MISSING
end


-- Builds a WWW-Authenticate value. With no token this is the bare challenge
-- that triggers the client's Kerberos exchange.
function _M.challenge(scheme, token)
  scheme = scheme or "Negotiate"
  if token and token ~= "" then
    return scheme .. " " .. ngx_encode_base64(token)
  end
  return scheme
end


-- Splits `user/instance@REALM` into its short name and realm.
function _M.split_principal(principal)
  local at = find(principal, "@", 1, true)
  if not at then
    return principal, nil
  end
  return sub(principal, 1, at - 1), sub(principal, at + 1)
end


-- Applies the configured normalisation and returns the identity used for
-- consumer lookup. The untouched principal is always kept separately so the
-- upstream header can carry the real thing.
function _M.identity(principal, conf)
  local user, realm = _M.split_principal(principal)

  local identity = conf.strip_realm and user or principal
  if conf.principal_lowercase then
    identity = lower(identity)
  end

  return identity, user, realm
end


-- Renders `${...}` placeholders in the consumer lookup template.
function _M.render_template(template, vars)
  local missing
  local rendered = gsub(template, "%${([%w_]+)}", function(name)
    local value = vars[name]
    if value == nil or value == "" then
      missing = missing or name
      return ""
    end
    return value
  end)

  if missing then
    return nil, "template placeholder '${" .. missing .. "}' resolved to nothing"
  end

  return rendered
end


-- Matches `value` against a list of patterns. A leading `~` marks a PCRE
-- pattern; everything else is compared literally.
function _M.matches_any(value, patterns, re_find)
  if not patterns or #patterns == 0 then
    return false
  end

  for _, pattern in ipairs(patterns) do
    if sub(pattern, 1, 1) == "~" then
      local expression = sub(pattern, 2)
      if re_find and re_find(value, expression, "jo") then
        return true
      end
    elseif value == pattern then
      return true
    end
  end

  return false
end


return _M
