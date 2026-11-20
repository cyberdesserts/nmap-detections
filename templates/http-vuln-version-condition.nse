local nmap = require "nmap"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"
local vulns = require "vulns"

description = [[
Template for a detection check that tests a product version AND a condition the
flaw needs, and reports one of four states per CVE.

Copy this file, rename it to http-vuln-cveYYYY-NNNNN.nse, and edit the four
blocks marked EDIT. Everything below the last EDIT block is shared logic and
should not need changing.

  EDIT 1  How the product identifies itself: the Server header patterns.
  EDIT 2  The CVEs: affected ranges, fixed versions, and any conditions the
          network cannot show.
  EDIT 3  The condition probe: a function that returns true, false or nil.
  EDIT 4  The script's own name, author and references.

As shipped, the template is filled in with the nginx2root values
(CVE-2026-123007 and CVE-2026-123633) and an HTTP/2 condition probe, so it can
be tested against lab/nginx2root and must give the same results as
nse/http-vuln-cve2026-123007.nse. That is the test that proves the template.

States, per CVE:
  LIKELY VULNERABLE  version in range and the condition is present
  NOT VULNERABLE     version out of range, or in range with the condition absent
  UNKNOWN            version hidden, condition could not be tested, or the CVE
                     needs conditions the network cannot show

Detection only. Write the condition probe so that it observes the condition
without sending anything that could trigger the flaw.
]]

---
-- @usage
-- nmap -Pn -p 80,443 --script ./http-vuln-version-condition.nse <target>
-- nmap -Pn -sV -p 8443 --script ./http-vuln-version-condition.nse --script-args vulns.showall <target>
--
-- @args http-vuln-version-condition.path Path for the HTTP request that reads
--       the Server header. Default: /

-- EDIT 4: identity. Rename these when you copy the file.
author = "Shakel Ahmed (CyberDesserts)"
license = "MIT. See the LICENSE file in the nmap-detections repository"
categories = {"vuln", "safe"}

portrule = shortport.http

------------------------------------------------------------------------------
-- EDIT 1: how the product identifies itself.
-- VERSION_PATTERN captures the dotted version from the Server header.
-- PRODUCT_ONLY_PATTERN matches the header when the product is named but the
-- version is hidden. Anything matching neither is treated as another product,
-- and the script stays silent for that port.
------------------------------------------------------------------------------
local PRODUCT = "NGINX"
local VERSION_PATTERN = "^nginx/([%d%.]+)"
local PRODUCT_ONLY_PATTERN = "^nginx%s*$"

------------------------------------------------------------------------------
-- EDIT 2: the CVEs.
-- ranges: list of {first affected, first fixed}. The fixed version is
-- exclusive. One range per branch that received its own fix.
-- unseen: set only when the CVE needs conditions a network scan cannot see.
-- When set, the best this CVE can reach is UNKNOWN, with this text shown.
------------------------------------------------------------------------------
local CHECKS = {
  {
    cve = "CVE-2026-123007",
    title = "NGINX HTTP/2 flow control memory corruption (nginx2root)",
    ranges = { {"1.9.5", "1.30.7"}, {"1.31.0", "1.31.9"} },
    fixed_text = "Fixed in 1.30.7 and 1.31.9.",
    references = {
      "https://www.cve.org/CVERecord?id=CVE-2026-123007",
      "https://nginx.org/en/security_advisories.html",
    },
    disclosure = {year = 2026, month = 11, day = 18},
  },
  {
    cve = "CVE-2026-123633",
    title = "NGINX HTTP/2 use-after-free (nginx2root)",
    ranges = { {"1.19.7", "1.30.7"}, {"1.31.0", "1.31.9"} },
    fixed_text = "Fixed in 1.30.7 and 1.31.9.",
    references = {
      "https://www.cve.org/CVERecord?id=CVE-2026-123633",
      "https://nginx.org/en/security_advisories.html",
    },
    disclosure = {year = 2026, month = 11, day = 18},
    unseen = "Exploitation also needs NGINX proxying requests to a backend "
      .. "and a worker process running short of worker_connections; this "
      .. "check cannot see either from the network.",
  },
}

------------------------------------------------------------------------------
-- EDIT 3: the condition probe.
-- Return two values: the result and a short label for the output.
--   true   the condition is present
--   false  the condition is absent
--   nil    could not tell (timeout, refused handshake, unexpected reply)
-- The example tests whether the port speaks HTTP/2: TLS ALPN on TLS ports,
-- the HTTP/2 connection preface (prior knowledge) on cleartext ports.
------------------------------------------------------------------------------
local CONDITION_NAME = "HTTP/2"

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

local function selected_alpn(ext)
  local ok, list = pcall(string.unpack, ">s2", ext)
  if not ok or #list == 0 then
    return nil
  end
  local ok2, proto = pcall(string.unpack, ">s1", list)
  return ok2 and proto or nil
end

local function alpn_offers_h2(host, port)
  local extensions = {
    application_layer_protocol_negotiation =
      tls.EXTENSION_HELPERS["application_layer_protocol_negotiation"]({"h2", "http/1.1"}),
    elliptic_curves = tls.EXTENSION_HELPERS["elliptic_curves"]({"ecdh_x25519", "secp256r1", "secp384r1"}),
    ec_point_formats = tls.EXTENSION_HELPERS["ec_point_formats"]({"uncompressed"}),
  }
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
  local buf, pos, result = "", 1, nil
  for _ = 1, 5 do
    local ok
    ok, buf = tls.record_buffer(sock, buf, pos)
    if not ok then
      break
    end
    local nextpos, record = tls.record_read(buf, pos)
    if not record or record.type == "alert" then
      break
    end
    pos = nextpos
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

local PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
local EMPTY_SETTINGS = string.pack(">I3 B B I4", 0, 0x4, 0, 0)

local function prior_knowledge_h2(host, port)
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
  if not ok or #data < 9 or data:sub(1, 5) == "HTTP/" then
    return false
  end
  return string.unpack("B", data, 4) == 0x4
end

local function condition(host, port)
  if shortport.ssl(host, port) then
    return alpn_offers_h2(host, port), "h2 via TLS ALPN"
  end
  return prior_knowledge_h2(host, port), "h2c, prior knowledge"
end

------------------------------------------------------------------------------
-- Shared logic below. No edits should be needed.
------------------------------------------------------------------------------

local function parse_version(text)
  local parts = {}
  for n in text:gmatch("%d+") do
    parts[#parts + 1] = tonumber(n)
  end
  return parts
end

-- Compares dotted versions of any length; missing parts count as 0.
local function vcmp(a, b)
  for i = 1, math.max(#a, #b) do
    local x, y = a[i] or 0, b[i] or 0
    if x ~= y then
      return x < y and -1 or 1
    end
  end
  return 0
end

local function in_ranges(v, ranges)
  for _, r in ipairs(ranges) do
    if vcmp(v, parse_version(r[1])) >= 0 and vcmp(v, parse_version(r[2])) < 0 then
      return true
    end
  end
  return false
end

local function range_text(ranges)
  local out = {}
  for _, r in ipairs(ranges) do
    out[#out + 1] = r[1] .. " up to but not including " .. r[2]
  end
  return table.concat(out, ", and ")
end

-- Returns: found (bool), version table or nil, version text or nil
local function read_version(host, port, path)
  local resp = http.get(host, port, path)
  local server = resp and resp.header and resp.header["server"]
  if not server then
    return false
  end
  local v = server:match(VERSION_PATTERN)
  if v then
    return true, parse_version(v), v
  end
  if server:match(PRODUCT_ONLY_PATTERN) then
    return true, nil, nil
  end
  return false
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local found, version, vtext = read_version(host, port, path)
  if not found then
    stdnse.debug1("Server header does not identify %s; skipping", PRODUCT)
    return nil
  end

  local cond, method = condition(host, port)
  stdnse.debug1("%s %s; %s (%s): %s", PRODUCT, vtext or "version hidden",
    CONDITION_NAME, method, tostring(cond))

  local cond_text = (cond == true and CONDITION_NAME .. " present (" .. method .. ")")
    or (cond == false and CONDITION_NAME .. " absent (" .. method .. ")")
    or CONDITION_NAME .. " could not be determined (" .. method .. ")"

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  for _, c in ipairs(CHECKS) do
    local vuln = {
      title = c.title,
      IDS = {CVE = c.cve},
      risk_factor = "High",
      dates = {disclosure = c.disclosure},
      references = c.references,
      extra_info = "Version taken from the Server header; backported fixes "
        .. "are not visible to this check.",
      state = vulns.STATE.NOT_VULN,
    }
    local tail = " Affected: " .. range_text(c.ranges) .. ". " .. c.fixed_text
    local unseen = c.unseen and (" " .. c.unseen) or ""

    if version == nil then
      if cond == false then
        vuln.description = PRODUCT .. " version hidden; " .. cond_text .. "." .. tail
      else
        vuln.state = vulns.STATE.UNKNOWN
        vuln.description = PRODUCT .. " version hidden; " .. cond_text
          .. ". Confirm the version on the host." .. unseen .. tail
      end
    elseif not in_ranges(version, c.ranges) then
      vuln.description = PRODUCT .. " " .. vtext .. " is outside the affected range." .. tail
    elseif cond == true and c.unseen then
      vuln.state = vulns.STATE.UNKNOWN
      vuln.description = PRODUCT .. " " .. vtext .. "; " .. cond_text .. "." .. unseen .. tail
    elseif cond == true then
      vuln.state = vulns.STATE.LIKELY_VULN
      vuln.description = PRODUCT .. " " .. vtext .. "; " .. cond_text .. "." .. tail
    elseif cond == false then
      vuln.description = PRODUCT .. " " .. vtext .. " is in range but " .. cond_text
        .. " for the name tested." .. tail
    else
      vuln.state = vulns.STATE.UNKNOWN
      vuln.description = PRODUCT .. " " .. vtext .. " is in range; " .. cond_text .. "." .. tail
    end
    report:add_vulns(SCRIPT_NAME, vuln)
  end
  return report:make_output()
end
