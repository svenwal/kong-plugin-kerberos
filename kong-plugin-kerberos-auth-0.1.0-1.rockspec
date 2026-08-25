package = "kong-plugin-kerberos-auth"
version = "0.1.0-1"

source = {
  url = "git+https://github.com/svenwal/kong-plugin-kerberos.git",
  tag = "0.1.0",
}

description = {
  summary = "Kerberos/SPNEGO authentication plugin for Kong",
  detailed = [[
    Terminates HTTP Negotiate (RFC 4559) authentication at Kong: validates the
    client's Kerberos service ticket against a keytab through the GSS-API and
    maps the authenticated principal onto a Kong consumer, so ACL, rate limiting
    and logging plugins work as they do behind any other auth plugin.
    Optionally re-authenticates to a Kerberos protected upstream, reusing the
    caller's delegated credential when one was sent.
  ]],
  homepage = "https://github.com/svenwal/kong-plugin-kerberos",
  license = "Apache-2.0",
}

dependencies = {
  "lua >= 5.1",
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.kerberos-auth.handler"]           = "kong/plugins/kerberos-auth/handler.lua",
    ["kong.plugins.kerberos-auth.schema"]            = "kong/plugins/kerberos-auth/schema.lua",
    ["kong.plugins.kerberos-auth.negotiate"]         = "kong/plugins/kerberos-auth/negotiate.lua",
    ["kong.plugins.kerberos-auth.consumer"]          = "kong/plugins/kerberos-auth/consumer.lua",
    ["kong.plugins.kerberos-auth.gssapi.ffi"]        = "kong/plugins/kerberos-auth/gssapi/ffi.lua",
    ["kong.plugins.kerberos-auth.gssapi.acceptor"]   = "kong/plugins/kerberos-auth/gssapi/acceptor.lua",
    ["kong.plugins.kerberos-auth.gssapi.initiator"]  = "kong/plugins/kerberos-auth/gssapi/initiator.lua",
  },
}
