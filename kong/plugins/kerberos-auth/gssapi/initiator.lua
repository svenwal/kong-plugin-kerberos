-- Initiator half of the GSS-API exchange: builds the SPNEGO token Kong sends
-- to a Kerberos protected upstream, either as itself (keytab identity) or as
-- the caller (delegated credential).

local gss = require "kong.plugins.kerberos-auth.gssapi.ffi"

local bit = require "bit"
local band = bit.band

local ffi_new = gss.new

local _M = {}


-- Initiator credentials hold a TGT, so they are cached per worker and refreshed
-- when the KDC reports them expired.
local cred_cache = {}


local function cache_key(opts)
  return (opts.keytab or "-") .. "|" .. (opts.client_principal or "*")
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


local function import_name(lib, name_string, prefer_principal)
  local name_type = (prefer_principal or string.find(name_string, "/", 1, true))
                    and gss.GSS_KRB5_NT_PRINCIPAL_NAME
                    or gss.GSS_C_NT_HOSTBASED_SERVICE

  local minor = ffi_new("OM_uint32[1]")
  local name = ffi_new("gss_name_t[1]")
  local buf = gss.buffer_from_string(name_string)

  local major = lib.gss_import_name(minor, buf, name_type, name)
  if gss.is_error(major) then
    return nil, "could not import name '" .. name_string .. "': "
                .. gss.status_string(lib, major, minor[0])
  end

  return name
end


-- Acquires (and caches) an initiator credential from a keytab.
--
-- Blocking note: this performs an AS-REQ against the KDC. It is called from
-- init_worker and from the timer refresh, and only falls into the request path
-- when both of those have failed.
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

  -- MIT obtains a TGT from this keytab automatically when the credential has
  -- no ccache entry yet.
  if opts.keytab and opts.keytab ~= "" then
    gss.setenv("KRB5_CLIENT_KTNAME", opts.keytab)
  end

  local desired_name, name_holder
  if opts.client_principal and opts.client_principal ~= "" then
    local imported, ierr = import_name(lib, opts.client_principal, true)
    if not imported then
      return nil, nil, ierr
    end
    name_holder = imported
    desired_name = imported[0]
  end

  -- Point the credential at a private in-process ccache, then put the
  -- environment back exactly as it was. A process wide KRB5CCNAME would also
  -- become the store for credentials clients delegate to the acceptor, which
  -- would mix the caller's forwarded TGT with Kong's own and silently
  -- authenticate the upstream leg as the wrong principal.
  local previous_ccache = os.getenv("KRB5CCNAME")
  gss.setenv("KRB5CCNAME", "MEMORY:kerberos-auth-initiator")

  local minor = ffi_new("OM_uint32[1]")
  local cred = ffi_new("gss_cred_id_t[1]")
  local major = lib.gss_acquire_cred(minor, desired_name, gss.GSS_C_INDEFINITE,
                                     nil, gss.GSS_C_INITIATE, cred, nil, nil)

  gss.setenv("KRB5CCNAME", previous_ccache)

  if name_holder then
    gss.release_name(lib, name_holder)
  end

  if gss.is_error(major) then
    return nil, nil, "could not acquire initiator credential for '"
                     .. tostring(opts.client_principal or "(default)") .. "': "
                     .. gss.status_string(lib, major, minor[0])
  end

  cred_cache[key] = { cred = cred, acquired_at = os.time() }

  return lib, cred
end


_M.acquire_credential = acquire


-- Builds the token for `target` (for example `HTTP@upstream.example.test`).
--
-- `opts.delegated` is a gss_cred_id_t[1] handed over by the acceptor; when
-- present Kong authenticates to the upstream as the original caller.
function _M.initiate(opts, target)
  local lib, cred, err

  if opts.delegated and opts.delegated[0] ~= nil then
    lib, err = gss.load(opts.library)
    if not lib then
      return nil, err
    end
    cred = opts.delegated

  else
    lib, cred, err = acquire(opts)
    if not lib then
      return nil, err
    end
  end

  local target_name, terr = import_name(lib, target)
  if not target_name then
    return nil, terr
  end

  local req_flags = 0
  if opts.mutual then
    req_flags = req_flags + gss.GSS_C_MUTUAL_FLAG
  end
  if opts.delegate then
    req_flags = req_flags + gss.GSS_C_DELEG_FLAG
  end

  -- Mechanism selection matters more than it looks. A credential delegated by
  -- the client carries a krb5 element only, and MIT's mechglue hands SPNEGO
  -- GSS_C_NO_CREDENTIAL when it cannot find a SPNEGO element -- SPNEGO then
  -- quietly falls back to the process default identity, so the upstream sees
  -- Kong instead of the caller. Credentials Kong acquires itself do carry a
  -- SPNEGO element, so they can negotiate normally.
  local mechanism = opts.mechanism
  if mechanism == nil or mechanism == "auto" then
    mechanism = opts.delegated and "krb5" or "spnego"
  end

  local mech_oid = mechanism == "krb5" and gss.GSS_MECH_KRB5 or gss.GSS_MECH_SPNEGO

  local minor = ffi_new("OM_uint32[1]")
  local ctx = ffi_new("gss_ctx_id_t[1]")
  local ret_flags = ffi_new("OM_uint32[1]")
  local output = gss.new_buffer()

  local major = lib.gss_init_sec_context(minor, cred[0], ctx, target_name[0],
                                         mech_oid, req_flags, 0,
                                         nil,   -- no channel bindings
                                         nil,   -- no input token, first leg
                                         nil,   -- actual mech not needed
                                         output, ret_flags, nil)

  local token = gss.buffer_to_string(output)
  gss.release_buffer(lib, output)
  gss.release_name(lib, target_name)
  gss.delete_context(lib, ctx)

  if gss.is_error(major) then
    local routine = gss.routine_error(major)
    local message = gss.status_string(lib, major, minor[0])

    if routine == "CREDENTIALS_EXPIRED" or routine == "NO_CRED" then
      _M.invalidate(opts)
    end

    return nil, "could not initiate context to '" .. target .. "': " .. message
  end

  -- CONTINUE_NEEDED here just means the upstream would answer with a mutual
  -- auth token. HTTP Negotiate clients send the first leg regardless, and the
  -- upstream's reply is informational for us.
  if not token then
    return nil, "GSS-API produced no token for '" .. target .. "'"
  end

  return token, nil, band(major, gss.GSS_S_CONTINUE_NEEDED) ~= 0
end


return _M
