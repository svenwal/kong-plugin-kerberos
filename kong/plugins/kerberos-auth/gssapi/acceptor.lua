-- Acceptor half of the GSS-API exchange: validates a SPNEGO/Kerberos token
-- sent by a client against a service keytab and returns the client principal.

local gss = require "kong.plugins.kerberos-auth.gssapi.ffi"

local bit = require "bit"
local band = bit.band

local ffi_new = gss.new

local _M = {}


-- Acceptor credentials are expensive to build (keytab file I/O) and valid for
-- the life of the worker, so they are cached per keytab + service principal.
-- Cache is worker local by design: gss_cred_id_t is a process handle and
-- cannot be shared through a shm zone.
local cred_cache = {}


local function cache_key(opts)
  return (opts.keytab or "-") .. "|" .. (opts.service_principal or "*")
end


function _M.invalidate(opts)
  local key = cache_key(opts)
  local entry = cred_cache[key]
  if entry then
    cred_cache[key] = nil
    local lib = gss.load(opts.library)
    if lib then
      gss.release_cred(lib, entry.cred)
    end
  end
end


-- Imports the configured service principal. `HTTP/host@REALM` is a Kerberos
-- principal name, `HTTP@host` is a host based service name; picking the wrong
-- name type produces a confusing BAD_NAME, so choose on the separator.
local function import_service_name(lib, principal)
  local name_type = string.find(principal, "/", 1, true)
                    and gss.GSS_KRB5_NT_PRINCIPAL_NAME
                    or gss.GSS_C_NT_HOSTBASED_SERVICE

  local minor = ffi_new("OM_uint32[1]")
  local name = ffi_new("gss_name_t[1]")
  local buf = gss.buffer_from_string(principal)

  local major = lib.gss_import_name(minor, buf, name_type, name)
  if gss.is_error(major) then
    return nil, "could not import service principal '" .. principal .. "': "
                .. gss.status_string(lib, major, minor[0])
  end

  return name
end


-- Returns the library handle and a cached acceptor credential.
local function acquire(opts)
  local lib, err = gss.load(opts.library)
  if not lib then
    return nil, nil, err
  end

  local key = cache_key(opts)
  local entry = cred_cache[key]
  if entry then
    return lib, entry.cred
  end

  -- MIT reads the acceptor keytab from process state captured at
  -- gss_acquire_cred time. There is no yield between these two calls, so a
  -- worker handling several plugin instances with different keytabs stays
  -- correct.
  if opts.keytab and opts.keytab ~= "" then
    local major = lib.krb5_gss_register_acceptor_identity(opts.keytab)
    if major ~= 0 then
      return nil, nil, "could not register acceptor keytab '" .. opts.keytab
                       .. "': " .. gss.status_string(lib, major, 0)
    end
  end

  -- With no desired name the acceptor matches any principal present in the
  -- keytab, which is what most deployments want.
  local desired_name, name_holder
  if opts.service_principal and opts.service_principal ~= "" then
    local imported, ierr = import_service_name(lib, opts.service_principal)
    if not imported then
      return nil, nil, ierr
    end
    name_holder = imported
    desired_name = imported[0]
  end

  local minor = ffi_new("OM_uint32[1]")
  local cred = ffi_new("gss_cred_id_t[1]")
  local major = lib.gss_acquire_cred(minor, desired_name, gss.GSS_C_INDEFINITE,
                                     nil, gss.GSS_C_ACCEPT, cred, nil, nil)

  if name_holder then
    gss.release_name(lib, name_holder)
  end

  if gss.is_error(major) then
    return nil, nil, "could not acquire acceptor credential (keytab '"
                     .. tostring(opts.keytab) .. "'): "
                     .. gss.status_string(lib, major, minor[0])
  end

  cred_cache[key] = { cred = cred, acquired_at = os.time() }

  return lib, cred
end


_M.acquire_credential = acquire


-- Returns the principal a credential handle represents, or nil. Used to make
-- delegation problems visible in the logs instead of silent identity swaps.
function _M.credential_name(lib, cred)
  if cred == nil or cred[0] == nil then
    return nil
  end

  local minor = ffi_new("OM_uint32[1]")
  local name = ffi_new("gss_name_t[1]")

  if gss.is_error(lib.gss_inquire_cred(minor, cred[0], name, nil, nil, nil)) then
    return nil
  end

  local display = gss.new_buffer()
  local major = lib.gss_display_name(minor, name[0], display, nil)
  local principal = not gss.is_error(major) and gss.buffer_to_string(display) or nil

  gss.release_buffer(lib, display)
  gss.release_name(lib, name)

  return principal
end


-- Returns the principal the credential represents, for startup diagnostics.
function _M.describe_credential(opts)
  local lib, cred, err = acquire(opts)
  if not lib then
    return nil, err
  end

  local minor = ffi_new("OM_uint32[1]")
  local name = ffi_new("gss_name_t[1]")
  local lifetime = ffi_new("OM_uint32[1]")

  local major = lib.gss_inquire_cred(minor, cred[0], name, lifetime, nil, nil)
  if gss.is_error(major) then
    return nil, gss.status_string(lib, major, minor[0])
  end

  local display = gss.new_buffer()
  major = lib.gss_display_name(minor, name[0], display, nil)
  local principal = not gss.is_error(major) and gss.buffer_to_string(display) or nil

  gss.release_buffer(lib, display)
  gss.release_name(lib, name)

  return principal or "(unnamed)", nil, tonumber(lifetime[0])
end


-- Validates `token` (raw bytes, already base64 decoded).
--
-- On success returns a table:
--   { principal, out_token, flags, delegated, lifetime }
-- On failure returns nil plus an error table carrying enough detail for both
-- the log line and the client facing challenge.
function _M.accept(opts, token)
  local lib, cred, err = acquire(opts)
  if not lib then
    return nil, { message = err, retryable = false }
  end

  local minor = ffi_new("OM_uint32[1]")
  local ctx = ffi_new("gss_ctx_id_t[1]")           -- GSS_C_NO_CONTEXT
  local src_name = ffi_new("gss_name_t[1]")
  local ret_flags = ffi_new("OM_uint32[1]")
  local lifetime = ffi_new("OM_uint32[1]")
  local delegated = ffi_new("gss_cred_id_t[1]")
  local output = gss.new_buffer()
  local input = gss.buffer_from_string(token)

  local major = lib.gss_accept_sec_context(minor, ctx, cred[0], input,
                                           nil,        -- no channel bindings
                                           src_name,
                                           nil,        -- mech type not needed
                                           output, ret_flags, lifetime,
                                           delegated)

  local out_token = gss.buffer_to_string(output)
  gss.release_buffer(lib, output)

  local function cleanup()
    gss.release_name(lib, src_name)
    gss.delete_context(lib, ctx)
  end

  if gss.is_error(major) then
    local routine = gss.routine_error(major)
    local message = gss.status_string(lib, major, minor[0])
    cleanup()
    gss.release_cred(lib, delegated)

    -- An expired or replaced keytab entry only shows up here; drop the cached
    -- credential so the next request rebuilds it.
    local retryable = routine == "CREDENTIALS_EXPIRED" or routine == "NO_CRED"
    if retryable then
      _M.invalidate(opts)
    end

    return nil, {
      message   = message,
      major     = tonumber(major),
      minor     = tonumber(minor[0]),
      routine   = routine,
      retryable = retryable,
    }
  end

  if band(major, gss.GSS_S_CONTINUE_NEEDED) ~= 0 then
    -- Multi leg SPNEGO (typically NTLM fallback). MIT cannot export a SPNEGO
    -- context, so the handle cannot survive to the next request and the
    -- exchange can never complete. Surface it clearly instead of looping.
    cleanup()
    gss.release_cred(lib, delegated)
    return nil, {
      message         = "multi-leg SPNEGO negotiation is not supported "
                        .. "(the client did not send a complete Kerberos token)",
      continue_needed = true,
      out_token       = out_token,
    }
  end

  local display = gss.new_buffer()
  local dmajor = lib.gss_display_name(minor, src_name[0], display, nil)
  if gss.is_error(dmajor) then
    local message = gss.status_string(lib, dmajor, minor[0])
    gss.release_buffer(lib, display)
    cleanup()
    gss.release_cred(lib, delegated)
    return nil, { message = "could not read client principal: " .. message }
  end

  local principal = gss.buffer_to_string(display)
  gss.release_buffer(lib, display)
  cleanup()

  local flags = tonumber(ret_flags[0])
  local result = {
    principal = principal,
    out_token = out_token,
    flags     = flags,
    lifetime  = tonumber(lifetime[0]),
    mutual    = band(flags, gss.GSS_C_MUTUAL_FLAG) ~= 0,
  }

  if band(flags, gss.GSS_C_DELEG_FLAG) ~= 0 and delegated[0] ~= nil then
    if opts.want_delegated then
      result.delegated = delegated
      result.delegated_name = _M.credential_name(lib, delegated)
    else
      gss.release_cred(lib, delegated)
    end
  else
    gss.release_cred(lib, delegated)
  end
  return result
end


-- Releases a delegated credential handed out by `accept`.
function _M.release_delegated(opts, result)
  if not result or not result.delegated then
    return
  end

  local lib = gss.load(opts.library)
  if lib then
    gss.release_cred(lib, result.delegated)
  end
  result.delegated = nil
end


return _M
