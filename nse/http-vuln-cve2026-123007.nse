local nmap = require "nmap"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"
local vulns = require "vulns"

description = [[
Checks NGINX Open Source for the two nginx2root HTTP/2 flaws, CVE-2026-123007
(memory corruption in HTTP/2 flow control) and CVE-2026-123633 (use-after-free
in HTTP/2). F5 fixed both on 18 November 2026 in 1.30.7 (stable) and 1.31.9
(mainline).

CVE-2026-123007 needs two things to be true at once, and both can be seen
from the network, so the script tests both:

1. The Server header reports an NGINX version inside an affected range.
2. The port speaks HTTP/2: over TLS, the server picks "h2" during ALPN; over
   cleartext, the server answers an HTTP/2 connection preface (h2c, prior
   knowledge).

A version banner alone produces false positives on every server with HTTP/2
switched off. For CVE-2026-123007 the script reports LIKELY VULNERABLE only
when both conditions hold, and NOT VULNERABLE (shown with vulns.showall) when
the version is in range but HTTP/2 is not offered on the port and name tested.

CVE-2026-123633 needs the same two conditions plus two more that the network
cannot show: NGINX proxying requests to a backend, and a worker process
running short of worker_connections. When the version is in range and HTTP/2
is on, the script reports CVE-2026-123633 as UNKNOWN and names the conditions
it could not check. It never reports CVE-2026-123633 as LIKELY VULNERABLE.

Detection only. The script sends one ordinary HTTP request, one TLS
ClientHello or one HTTP/2 connection preface. It sends no malformed frames
and does not attempt to trigger either flaw.

Limitations:
* Distribution packages backport fixes without changing the version string
  (for example Debian or Ubuntu builds). A backported build reports LIKELY
  VULNERABLE here. Confirm against the distribution's advisory.
* With server_tokens off the version is hidden. If HTTP/2 is on, the script
  reports the result as UNKNOWN rather than guessing.
* NGINX Plus, OpenResty and other forks use their own version strings and
  are not assessed.
* HTTP/2 is enabled per server block. Scan by hostname so the TLS SNI and Host
  header select the right virtual host; other names on the same port may
  differ.
* ALPN is read from the TLS 1.2 ServerHello. A TLS 1.3-only listener hides
  ALPN in encrypted extensions, so HTTP/2 status is reported as unknown.
]]

---
-- @usage
-- nmap -p 80,443 --script http-vuln-cve2026-123007 <target>
-- nmap -p 443 --script http-vuln-cve2026-123007 --script-args vulns.showall <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | http-vuln-cve2026-123007:
-- |   VULNERABLE:
-- |   NGINX HTTP/2 flow control memory corruption (nginx2root)
-- |     State: LIKELY VULNERABLE
-- |     IDs:  CVE:CVE-2026-123007
-- |     Risk factor: High
-- |       NGINX 1.31.8 negotiated HTTP/2 (h2 via TLS ALPN). Affected range for this
-- |       CVE: 1.9.5 to 1.30.6 and 1.31.0 to 1.31.8. Fixed in 1.30.7 and 1.31.9.
-- |     Disclosure date: 2026-11-18
-- |     Extra information:
-- |       Version taken from the Server header; backported distribution fixes are
-- |       not visible to this check. Restart NGINX after upgrading.
--
-- @args http-vuln-cve2026-123007.path Path for the HTTP request that reads the
--       Server header. Default: /

author = "Shakel Ahmed (CyberDesserts)"
license = "MIT. See the LICENSE file in the cyberdesserts-detections repository"
categories = {"vuln", "safe"}

portrule = shortport.http

-- Fixed releases are the same for both CVEs: 1.30.7 on stable, 1.31.9 on
-- mainline. Only the first affected version differs.
local CHECKS = {
  {
    cve = "CVE-2026-123007",
    title = "NGINX HTTP/2 flow control memory corruption (nginx2root)",
    first = {1, 9, 5},
    range_text = "1.9.5 to 1.30.6 and 1.31.0 to 1.31.8",
  },
  {
    cve = "CVE-2026-123633",
    title = "NGINX HTTP/2 use-after-free (nginx2root)",
    first = {1, 19, 7},
    range_text = "1.19.7 to 1.30.6 and 1.31.0 to 1.31.8",
    -- Conditions the network cannot show. When set, an in-range server with
    -- HTTP/2 on is reported UNKNOWN rather than LIKELY VULNERABLE.
    unseen = "Exploitation also needs NGINX proxying requests to a backend "
      .. "and a worker process running short of worker_connections; this "
      .. "check cannot see either from the network.",
  },
}

local STABLE_FIX = {1, 30, 7}
local MAINLINE_START = {1, 31, 0}
local MAINLINE_FIX = {1, 31, 9}

-- Returns -1, 0 or 1 comparing two {major, minor, patch} lists.
local function vcmp(a, b)
  for i = 1, 3 do
    if a[i] ~= b[i] then
      return a[i] < b[i] and -1 or 1
    end
  end
  return 0
end

local function in_range(v, first)
  if vcmp(v, first) < 0 then
    return false
  end
  if vcmp(v, STABLE_FIX) < 0 then
    return true
  end
  return vcmp(v, MAINLINE_START) >= 0 and vcmp(v, MAINLINE_FIX) < 0
end

-- Reads the Server header. Returns:
--   "nginx", {maj, min, patch}  when the version is visible
--   "nginx", nil                when the product is visible but not the version
--   nil                         when the server is not NGINX Open Source
local function nginx_version(host, port, path)
  local resp = http.get(host, port, path)
  local server = resp and resp.header and resp.header["server"]
  if not server then
    return nil
  end
  local maj, min, patch = server:match("^nginx/(%d+)%.(%d+)%.(%d+)")
  if maj then
    return "nginx", {tonumber(maj), tonumber(min), tonumber(patch)}, server
  end
  if server:match("^nginx%s*$") then
    return "nginx", nil, server
  end
  return nil
end

-- ALPN extension data (RFC 7301): a two-byte list length, then one
-- length-prefixed protocol name chosen by the server.
local function selected_alpn(ext)
  local ok, list = pcall(string.unpack, ">s2", ext)
  if not ok or #list == 0 then
    return nil
  end
  local ok2, proto = pcall(string.unpack, ">s1", list)
  return ok2 and proto or nil
end

-- The cipher list is set here rather than inherited from tls.lua, whose
-- default has changed between Nmap releases. A server on a modern profile
-- (ECDHE with AEAD ciphers only, as in Mozilla's "intermediate" configuration)
-- refuses a hello it shares no cipher with, and the ALPN answer is never seen.
-- AEAD suites go first, with two legacy suites kept as a fallback.
local MODERN_TLS12_CIPHERS = {
  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
  "TLS_RSA_WITH_AES_128_GCM_SHA256",
  "TLS_RSA_WITH_AES_128_CBC_SHA",
}

-- Offers h2 and http/1.1 in a TLS 1.2 ClientHello and returns:
--   true   server selected h2
--   false  server completed the hello without selecting h2
--   nil    could not tell (no TLS 1.2 ServerHello, timeout, alert)
local function h2_over_tls(host, port)
  -- Supported groups and point formats are sent explicitly: some TLS 1.2
  -- servers refuse an ECDHE handshake without them.
  local extensions = {
    application_layer_protocol_negotiation =
      tls.EXTENSION_HELPERS["application_layer_protocol_negotiation"]({"h2", "http/1.1"}),
    elliptic_curves = tls.EXTENSION_HELPERS["elliptic_curves"]({"ecdh_x25519", "secp256r1", "secp384r1"}),
    ec_point_formats = tls.EXTENSION_HELPERS["ec_point_formats"]({"uncompressed"}),
  }
  -- SNI only when scanning by name; an IP target has no server name to send.
  local sni = tls.servername(host)
  if sni then
    extensions.server_name = tls.EXTENSION_HELPERS["server_name"](sni)
  end
  local hello = tls.client_hello({
    protocol = "TLSv1.2",
    ciphers = MODERN_TLS12_CIPHERS,
    extensions = extensions,
  })

  local sock = nmap.new_socket()
  sock:set_timeout(5000)
  if not sock:connect(host, port) then
    return nil
  end
  if not sock:send(hello) then
    sock:close()
    return nil
  end

  local buf, pos = "", 1
  local result = nil
  for _ = 1, 5 do
    local ok
    ok, buf = tls.record_buffer(sock, buf, pos)
    if not ok then
      stdnse.debug2("TLS read failed: %s", tostring(buf))
      break
    end
    local nextpos, record = tls.record_read(buf, pos)
    if not record then
      break
    end
    pos = nextpos
    if record.type == "alert" then
      local a = record.body and record.body[1]
      stdnse.debug2("TLS alert from server: %s", a and tostring(a.description) or "?")
      break
    end
    if record.type == "handshake" then
      for _, msg in ipairs(record.body) do
        if msg.type == "server_hello" then
          local ext = msg.extensions and
            msg.extensions["application_layer_protocol_negotiation"]
          result = (ext ~= nil and selected_alpn(ext) == "h2")
          break
        end
      end
      if result ~= nil then
        break
      end
    end
  end
  sock:close()
  return result
end

-- Sends the HTTP/2 client connection preface followed by an empty SETTINGS
-- frame (RFC 9113, section 3.4). A server speaking h2c answers with a
-- SETTINGS frame, frame type 0x4. An HTTP/1.x server answers with text or
-- closes the connection.
local PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
local EMPTY_SETTINGS = string.pack(">I3 B B I4", 0, 0x4, 0, 0)

local function h2c_prior_knowledge(host, port)
  local sock = nmap.new_socket()
  sock:set_timeout(5000)
  if not sock:connect(host, port) then
    return nil
  end
  if not sock:send(PREFACE .. EMPTY_SETTINGS) then
    sock:close()
    return nil
  end
  local ok, data = sock:receive_bytes(9)
  sock:close()
  if not ok or #data < 9 then
    return false
  end
  if data:sub(1, 5) == "HTTP/" then
    return false
  end
  local frame_type = string.unpack("B", data, 4)
  return frame_type == 0x4
end

local function http2_status(host, port)
  if shortport.ssl(host, port) then
    return h2_over_tls(host, port), "h2 via TLS ALPN"
  end
  return h2c_prior_knowledge(host, port), "h2c, prior knowledge"
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"

  local product, version, banner = nginx_version(host, port, path)
  if not product then
    stdnse.debug1("Server header does not identify NGINX Open Source; skipping")
    return nil
  end

  local h2, method = http2_status(host, port)
  stdnse.debug1("Server: %s; HTTP/2 (%s): %s", banner, method, tostring(h2))

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local vtext = version and table.concat(version, ".") or nil

  for _, c in ipairs(CHECKS) do
    local vuln = {
      title = c.title,
      IDS = {CVE = c.cve},
      risk_factor = "High",
      dates = {disclosure = {year = 2026, month = 11, day = 18}},
      references = {
        "https://www.cve.org/CVERecord?id=" .. c.cve,
        "https://nginx.org/en/security_advisories.html",
      },
      extra_info = "Version taken from the Server header; backported "
        .. "distribution fixes are not visible to this check. Restart NGINX "
        .. "after upgrading.",
      state = vulns.STATE.NOT_VULN,
    }

    local h2_text = (h2 == true and "negotiated HTTP/2 (" .. method .. ")")
      or (h2 == false and "did not offer HTTP/2 (" .. method .. ")")
      or "HTTP/2 status could not be determined (" .. method .. ")"
    local fix_text = " Affected range for this CVE: " .. c.range_text
      .. ". Fixed in 1.30.7 and 1.31.9."

    if version == nil then
      if h2 == false then
        vuln.description = "NGINX version hidden; " .. h2_text .. "." .. fix_text
      else
        vuln.state = vulns.STATE.UNKNOWN
        vuln.description = "NGINX version hidden (server_tokens off); "
          .. h2_text .. ". Confirm the version on the host."
          .. (c.unseen and (" " .. c.unseen) or "") .. fix_text
      end
    elseif not in_range(version, c.first) then
      vuln.description = "NGINX " .. vtext .. " is outside the affected range." .. fix_text
    elseif h2 == true and c.unseen then
      vuln.state = vulns.STATE.UNKNOWN
      vuln.description = "NGINX " .. vtext .. " " .. h2_text .. ". " .. c.unseen
        .. fix_text
    elseif h2 == true then
      vuln.state = vulns.STATE.LIKELY_VULN
      vuln.description = "NGINX " .. vtext .. " " .. h2_text .. "." .. fix_text
    elseif h2 == false then
      vuln.description = "NGINX " .. vtext .. " is in range but " .. h2_text
        .. " for the name tested. Other virtual hosts on this port may differ;"
        .. " upgrade regardless." .. fix_text
    else
      vuln.state = vulns.STATE.UNKNOWN
      vuln.description = "NGINX " .. vtext .. " is in range; " .. h2_text .. "." .. fix_text
    end

    report:add_vulns(SCRIPT_NAME, vuln)
  end

  return report:make_output()
end
