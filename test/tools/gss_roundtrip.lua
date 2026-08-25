-- Standalone GSS-API round trip: initiate a SPNEGO token as kong-client and
-- accept it with the HTTP/kong.example.test keytab, all in one process.
-- Run inside the Kong container to validate the FFI layer without Kong.

package.path = "/opt/kong-plugin/?.lua;" .. package.path

local gss       = require "kong.plugins.kerberos-auth.gssapi.ffi"
local acceptor  = require "kong.plugins.kerberos-auth.gssapi.acceptor"
local initiator = require "kong.plugins.kerberos-auth.gssapi.initiator"

local KEYTAB = os.getenv("KEYTAB") or "/keytabs/kong.keytab"
local TARGET = os.getenv("TARGET") or "HTTP@kong.example.test"

local failures = 0

local function check(label, ok, detail)
  print(string.format("%-52s %s%s", label, ok and "PASS" or "FAIL",
                      detail and ("  (" .. tostring(detail) .. ")") or ""))
  if not ok then
    failures = failures + 1
  end
end

gss.setenv("KRB5_CONFIG", "/etc/krb5.conf")
gss.setenv("KRB5CCNAME", "MEMORY:kerberos-auth")
gss.setenv("KRB5RCACHETYPE", "none")

local lib, err = gss.load()
check("load libgssapi", lib ~= nil, err)
if not lib then os.exit(1) end

local acceptor_opts = { keytab = KEYTAB, service_principal = "HTTP@kong.example.test" }

local principal, derr = acceptor.describe_credential(acceptor_opts)
check("acquire acceptor credential", principal ~= nil, derr or principal)

local token, ierr = initiator.initiate({
  keytab = KEYTAB,
  client_principal = "kong-client@EXAMPLE.TEST",
  mutual = true,
  delegate = true,
}, TARGET)
check("initiate SPNEGO token", token ~= nil, ierr or (#(token or "") .. " bytes"))
if not token then os.exit(1) end

local result, aerr = acceptor.accept({
  keytab = KEYTAB,
  service_principal = "HTTP@kong.example.test",
  want_delegated = true,
}, token)
check("accept SPNEGO token", result ~= nil, aerr and aerr.message)
if not result then os.exit(1) end

check("principal is kong-client@EXAMPLE.TEST",
      result.principal == "kong-client@EXAMPLE.TEST", result.principal)
check("mutual auth token returned", result.out_token ~= nil and #result.out_token > 0)

-- The acceptor must be internally consistent: a delegated handle exactly when
-- the peer set the delegation flag. Whether delegation happens at all depends
-- on the client and the KDC, which the end to end suite covers with a real
-- curl --delegation always.
local bit = require "bit"
local deleg_flag = bit.band(result.flags, gss.GSS_C_DELEG_FLAG) ~= 0
check("delegated handle matches the delegation flag",
      deleg_flag == (result.delegated ~= nil),
      "flag=" .. tostring(deleg_flag) .. " handle=" .. tostring(result.delegated ~= nil))

-- Garbage must be rejected cleanly, never raise.
local bad, berr = acceptor.accept(acceptor_opts, "not-a-kerberos-token")
check("garbage token rejected", bad == nil and berr ~= nil and berr.message ~= nil,
      berr and berr.message)

-- A wrong keytab must produce a readable error, not a crash.
local _, kerr = acceptor.accept({ keytab = "/keytabs/missing.keytab" }, token)
check("missing keytab reports readable error",
      kerr ~= nil and kerr.message ~= nil, kerr and kerr.message)

-- Repeat the happy path to prove the cached credential still works.
local again = acceptor.accept(acceptor_opts, select(1, initiator.initiate({
  keytab = KEYTAB, client_principal = "kong-client@EXAMPLE.TEST",
}, TARGET)))
check("second round trip with cached credential", again ~= nil,
      again and again.principal)

print(string.rep("-", 70))
if failures > 0 then
  print(failures .. " check(s) failed")
  os.exit(1)
end
print("all checks passed")
