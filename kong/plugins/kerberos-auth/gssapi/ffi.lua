-- Low level LuaJIT FFI binding for the MIT Kerberos GSS-API.
--
-- This module owns every `ffi.cdef` and the library handle cache. Higher level
-- modules (acceptor, initiator) speak in Lua strings and tables and never touch
-- raw cdata lifetimes themselves.

local ffi = require "ffi"
local bit = require "bit"

local band = bit.band
local ffi_new = ffi.new
local ffi_cast = ffi.cast
local ffi_string = ffi.string

local _M = {}


-- `ffi.cdef` is process global and errors on redefinition, which happens when
-- Kong reloads plugin modules. Guard it so a reload is a no-op.
local cdef_ok, cdef_err = pcall(ffi.cdef, [[
typedef uint32_t OM_uint32;

typedef struct gss_name_struct            *gss_name_t;
typedef struct gss_cred_id_struct         *gss_cred_id_t;
typedef struct gss_ctx_id_struct          *gss_ctx_id_t;
typedef struct gss_channel_bindings_struct *gss_channel_bindings_t;

typedef struct gss_OID_desc_struct {
  OM_uint32 length;
  void     *elements;
} gss_OID_desc, *gss_OID;

typedef struct gss_OID_set_desc_struct {
  size_t   count;
  gss_OID  elements;
} gss_OID_set_desc, *gss_OID_set;

typedef struct gss_buffer_desc_struct {
  size_t  length;
  void   *value;
} gss_buffer_desc, *gss_buffer_t;

OM_uint32 gss_import_name(OM_uint32 *minor, gss_buffer_t input_name,
                          gss_OID input_name_type, gss_name_t *output_name);

OM_uint32 gss_display_name(OM_uint32 *minor, gss_name_t input_name,
                           gss_buffer_t output_name, gss_OID *output_name_type);

OM_uint32 gss_acquire_cred(OM_uint32 *minor, gss_name_t desired_name,
                           OM_uint32 time_req, gss_OID_set desired_mechs,
                           int cred_usage, gss_cred_id_t *output_cred,
                           gss_OID_set *actual_mechs, OM_uint32 *time_rec);

OM_uint32 gss_acquire_cred_with_password(OM_uint32 *minor, gss_name_t desired_name,
                                         gss_buffer_t password, OM_uint32 time_req,
                                         gss_OID_set desired_mechs, int cred_usage,
                                         gss_cred_id_t *output_cred,
                                         gss_OID_set *actual_mechs, OM_uint32 *time_rec);

OM_uint32 gss_accept_sec_context(OM_uint32 *minor, gss_ctx_id_t *context_handle,
                                 gss_cred_id_t acceptor_cred, gss_buffer_t input_token,
                                 gss_channel_bindings_t input_chan_bindings,
                                 gss_name_t *src_name, gss_OID *mech_type,
                                 gss_buffer_t output_token, OM_uint32 *ret_flags,
                                 OM_uint32 *time_rec, gss_cred_id_t *delegated_cred);

OM_uint32 gss_init_sec_context(OM_uint32 *minor, gss_cred_id_t claimant_cred,
                               gss_ctx_id_t *context_handle, gss_name_t target_name,
                               gss_OID mech_type, OM_uint32 req_flags, OM_uint32 time_req,
                               gss_channel_bindings_t input_chan_bindings,
                               gss_buffer_t input_token, gss_OID *actual_mech_type,
                               gss_buffer_t output_token, OM_uint32 *ret_flags,
                               OM_uint32 *time_rec);

OM_uint32 gss_inquire_cred(OM_uint32 *minor, gss_cred_id_t cred_handle,
                           gss_name_t *name, OM_uint32 *lifetime, int *cred_usage,
                           gss_OID_set *mechanisms);

OM_uint32 gss_display_status(OM_uint32 *minor, OM_uint32 status_value, int status_type,
                             gss_OID mech_type, OM_uint32 *message_context,
                             gss_buffer_t status_string);

OM_uint32 gss_release_name(OM_uint32 *minor, gss_name_t *name);
OM_uint32 gss_release_buffer(OM_uint32 *minor, gss_buffer_t buffer);
OM_uint32 gss_release_cred(OM_uint32 *minor, gss_cred_id_t *cred_handle);
OM_uint32 gss_release_oid_set(OM_uint32 *minor, gss_OID_set *set);
OM_uint32 gss_delete_sec_context(OM_uint32 *minor, gss_ctx_id_t *context_handle,
                                 gss_buffer_t output_token);

/* MIT specific: selects the acceptor keytab for subsequent gss_acquire_cred
   calls without going through the KRB5_KTNAME environment variable. */
OM_uint32 krb5_gss_register_acceptor_identity(const char *keytab_path);

int setenv(const char *name, const char *value, int overwrite);
int unsetenv(const char *name);
]])

if not cdef_ok and not string.find(tostring(cdef_err), "redefine", 1, true) then
  error("kerberos-auth: failed to declare GSS-API bindings: " .. tostring(cdef_err))
end


---------------------------------------------------------------------------
-- Constants
---------------------------------------------------------------------------

_M.GSS_S_COMPLETE         = 0
_M.GSS_S_CONTINUE_NEEDED  = 1

-- Routine errors occupy bits 16-23, calling errors bits 24-31.
local GSS_ERROR_MASK      = 0xFFFF0000
_M.GSS_ERROR_MASK         = GSS_ERROR_MASK

_M.GSS_C_GSS_CODE         = 1
_M.GSS_C_MECH_CODE        = 2

_M.GSS_C_BOTH             = 0
_M.GSS_C_INITIATE         = 1
_M.GSS_C_ACCEPT           = 2

_M.GSS_C_INDEFINITE       = 0xFFFFFFFF

_M.GSS_C_DELEG_FLAG       = 1
_M.GSS_C_MUTUAL_FLAG      = 2
_M.GSS_C_REPLAY_FLAG      = 4
_M.GSS_C_SEQUENCE_FLAG    = 8
_M.GSS_C_CONF_FLAG        = 16
_M.GSS_C_INTEG_FLAG       = 32

-- Routine error codes, already shifted into place, for the friendly messages.
local ROUTINE_ERRORS = {
  [1]  = "BAD_MECH",
  [2]  = "BAD_NAME",
  [3]  = "BAD_NAMETYPE",
  [4]  = "BAD_BINDINGS",
  [5]  = "BAD_STATUS",
  [6]  = "BAD_MIC",
  [7]  = "NO_CRED",
  [8]  = "NO_CONTEXT",
  [9]  = "DEFECTIVE_TOKEN",
  [10] = "DEFECTIVE_CREDENTIAL",
  [11] = "CREDENTIALS_EXPIRED",
  [12] = "CONTEXT_EXPIRED",
  [13] = "FAILURE",
  [14] = "BAD_QOP",
  [15] = "UNAUTHORIZED",
  [16] = "UNAVAILABLE",
  [17] = "DUPLICATE_ELEMENT",
  [18] = "NAME_NOT_MN",
}

_M.GSS_S_NO_CRED             = 7 * 65536
_M.GSS_S_DEFECTIVE_TOKEN     = 9 * 65536
_M.GSS_S_CREDENTIALS_EXPIRED = 11 * 65536


-- DER encoded OID bodies. The Lua strings must outlive every gss_OID_desc that
-- points into them, so they are anchored in this module-level table.
local OID_BYTES = {
  hostbased_service = "\42\134\72\134\247\18\1\2\1\4",  -- 1.2.840.113554.1.2.1.4
  user_name         = "\42\134\72\134\247\18\1\2\1\1",  -- 1.2.840.113554.1.2.1.1
  krb5_principal    = "\42\134\72\134\247\18\1\2\2\1",  -- 1.2.840.113554.1.2.2.1
  spnego            = "\43\6\1\5\5\2",                  -- 1.3.6.1.5.5.2
  krb5              = "\42\134\72\134\247\18\1\2\2",    -- 1.2.840.113554.1.2.2
}
_M.OID_BYTES = OID_BYTES

local function make_oid(bytes)
  local oid = ffi_new("gss_OID_desc[1]")
  oid[0].length = #bytes
  oid[0].elements = ffi_cast("void *", bytes)
  return oid
end

-- Built once at load time; the OID_BYTES table keeps the backing strings alive.
_M.GSS_C_NT_HOSTBASED_SERVICE = make_oid(OID_BYTES.hostbased_service)
_M.GSS_C_NT_USER_NAME         = make_oid(OID_BYTES.user_name)
_M.GSS_KRB5_NT_PRINCIPAL_NAME = make_oid(OID_BYTES.krb5_principal)
_M.GSS_MECH_SPNEGO            = make_oid(OID_BYTES.spnego)
_M.GSS_MECH_KRB5              = make_oid(OID_BYTES.krb5)


---------------------------------------------------------------------------
-- Library loading
---------------------------------------------------------------------------

-- Kong's Ubuntu image ships the runtime soname only (no `.so` dev symlink), so
-- the versioned name has to come first.
local DEFAULT_LIBRARIES = {
  "libgssapi_krb5.so.2",
  "libgssapi_krb5.so",
  "/usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2",
  "/usr/lib/aarch64-linux-gnu/libgssapi_krb5.so.2",
  "libgssapi.so.3",
}

local lib_cache = {}

-- Loads (and caches) the GSS-API shared library. `preferred` comes from the
-- plugin config and is tried before the built-in fallbacks.
function _M.load(preferred)
  local key = preferred or "@default"
  local cached = lib_cache[key]
  if cached ~= nil then
    if cached == false then
      return nil, "GSS-API library could not be loaded (cached failure)"
    end
    return cached
  end

  local candidates = {}
  if preferred and preferred ~= "" then
    candidates[#candidates + 1] = preferred
  end
  for _, name in ipairs(DEFAULT_LIBRARIES) do
    candidates[#candidates + 1] = name
  end

  local tried = {}
  for _, name in ipairs(candidates) do
    local ok, handle = pcall(ffi.load, name)
    if ok then
      lib_cache[key] = handle
      return handle
    end
    tried[#tried + 1] = name
  end

  lib_cache[key] = false
  return nil, "could not load GSS-API library, tried: " .. table.concat(tried, ", ")
end


---------------------------------------------------------------------------
-- Buffer helpers
---------------------------------------------------------------------------

-- Wraps a Lua string in a gss_buffer_desc. The returned anchor table must stay
-- reachable for as long as the buffer is passed to the library, otherwise the
-- backing string can be collected while C still points at it.
function _M.buffer_from_string(str)
  local buf = ffi_new("gss_buffer_desc[1]")
  if str == nil or #str == 0 then
    buf[0].length = 0
    buf[0].value = nil
    return buf, nil
  end
  buf[0].length = #str
  buf[0].value = ffi_cast("void *", str)
  return buf, str
end


function _M.buffer_to_string(buf)
  if buf == nil or buf[0].value == nil or buf[0].length == 0 then
    return nil
  end
  return ffi_string(buf[0].value, buf[0].length)
end


function _M.new_buffer()
  return ffi_new("gss_buffer_desc[1]")
end


function _M.release_buffer(lib, buf)
  if buf ~= nil and buf[0].value ~= nil then
    local minor = ffi_new("OM_uint32[1]")
    lib.gss_release_buffer(minor, buf)
  end
end


function _M.release_name(lib, name)
  if name ~= nil and name[0] ~= nil then
    local minor = ffi_new("OM_uint32[1]")
    lib.gss_release_name(minor, name)
    name[0] = nil
  end
end


function _M.release_cred(lib, cred)
  if cred ~= nil and cred[0] ~= nil then
    local minor = ffi_new("OM_uint32[1]")
    lib.gss_release_cred(minor, cred)
    cred[0] = nil
  end
end


function _M.delete_context(lib, ctx)
  if ctx ~= nil and ctx[0] ~= nil then
    local minor = ffi_new("OM_uint32[1]")
    lib.gss_delete_sec_context(minor, ctx, nil)
    ctx[0] = nil
  end
end


---------------------------------------------------------------------------
-- Status handling
---------------------------------------------------------------------------

function _M.is_error(major)
  return band(major, GSS_ERROR_MASK) ~= 0
end


function _M.routine_error(major)
  local code = band(major, 0x00FF0000) / 65536
  return ROUTINE_ERRORS[code]
end


-- Renders both halves of a GSS status pair into a single human readable line.
-- Kerberos failures are near impossible to diagnose without this, so it is
-- called on every error path.
local function display(lib, status, status_type)
  local parts = {}
  local minor = ffi_new("OM_uint32[1]")
  local message_context = ffi_new("OM_uint32[1]")

  repeat
    local buf = _M.new_buffer()
    local maj = lib.gss_display_status(minor, status, status_type, nil,
                                       message_context, buf)
    if band(maj, GSS_ERROR_MASK) ~= 0 then
      _M.release_buffer(lib, buf)
      break
    end

    local text = _M.buffer_to_string(buf)
    if text then
      parts[#parts + 1] = text
    end
    _M.release_buffer(lib, buf)
  until message_context[0] == 0 or #parts > 8

  return table.concat(parts, "; ")
end


function _M.status_string(lib, major, minor)
  local pieces = {}

  local routine = _M.routine_error(major)
  if routine then
    pieces[#pieces + 1] = "GSS_S_" .. routine
  end

  local gss_text = display(lib, major, _M.GSS_C_GSS_CODE)
  if gss_text ~= "" then
    pieces[#pieces + 1] = gss_text
  end

  if minor and minor ~= 0 then
    local mech_text = display(lib, minor, _M.GSS_C_MECH_CODE)
    if mech_text ~= "" then
      pieces[#pieces + 1] = mech_text
    end
  end

  if #pieces == 0 then
    return string.format("GSS-API failure (major=0x%08x, minor=%d)", major, minor or 0)
  end

  return table.concat(pieces, ": ")
end


---------------------------------------------------------------------------
-- Environment
---------------------------------------------------------------------------

-- nginx workers inherit a scrubbed environment, and the krb5 library reads
-- these at call time, so setting them from Lua at init is both necessary and
-- sufficient.
function _M.setenv(name, value)
  if value == nil then
    ffi.C.unsetenv(name)
    return
  end
  ffi.C.setenv(name, value, 1)
end


_M.new = ffi_new
_M.cast = ffi_cast

return _M
