local dns = require "dns"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Retrieves information from a DNS nameserver and also checks against CVE-2020-1350 for Microsoft SigRED issue
 This script performs the same queries as the following
dig commands:
  - dig CH TXT bind.version @target

References:
Based on - https://nmap.org/nsedoc/scripts/dns-nsid.html authored by John R. Bond
]]

author = "Pr4jwal (@psc4re)"


---
-- @usage
-- nmap -sSU -p 53 --script cve-2020-1350.nse --script-args output='report.txt'
--
-- @output
-- 53/tcp open  domain
-- cve-2020-1350:
--  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
--  CVE-2020-1350: [+] VULNERABLE
--
-- @xmloutput
-- <table key="microsoft-dns-version">
-- <elem key="bind.version">Microsoft DNS 6.1.7601 (1DB15D39)</elem>
-- <elem key="cve-2020-1350">[+] VULNERABLE</elem>



categories = {"discovery", "default", "safe"}


portrule = function (host, port)
  if not shortport.port_or_service(53, "domain", {"tcp", "udp"})(host, port) then
    return false
  end
  -- only check tcp if udp is not open or open|filtered
  if port.protocol == 'tcp' then
    local tmp_port = nmap.get_port_state(host, {number=port.number, protocol="udp"})
    if tmp_port then
      return not string.match(tmp_port.state, '^open')
    end
  end
  return true
end

function Set (list)
  local set = {}
  for _, l in ipairs(list) do set[l] = true end
  return set
end

action = function(host, port)
  local outputFile = stdnse.get_script_args(SCRIPT_NAME..".output") or nil
  local result = stdnse.output_table()
  local flag = false
  local reportwrite
  local vulvalue = Set {"1DB15F75", "17725FAC", "17714726", "1773501D", "1DB1446A", "1DB14556", "1DB15CD4", "1DB15EC5", "1DB15D39", "1DB154B9", "1DB14A66", "1DB15B4F","17724D35","1DB04001","17714650", "17724655", "17724836", "1772487D", "1DB04228", "1DB144E7" }
  local status, bind_version = dns.query("version.bind", {host = host.ip, port=port.number, proto=port.protocol, dtype='TXT', class=dns.CLASS.CH})
  if ( status ) then
    flag = true
    result["bind.version"] = bind_version
    local matched = string.match(bind_version, "%(([^%)]+)%)")
    local mic = string.match(bind_version, "Microsoft")
    if mic == "Microsoft" then
      if vulvalue[matched] then
        result["CVE-2020-1350"] = "[+] VULNERABLE"
        reportwrite = "[+] "..host.ip..": is vulnerable to CVE-2020-1350 SiGRED : "..bind_version
      else
        result["CVE-2020-1350"] = "[-] Likely VULNERABLE"
        reportwrite = "[-] "..host.ip..": is Likely vulnerable to CVE-2020-1350 SiGRED : "..bind_version
      end
    end
    if (outputFile and (reportwrite ~= nil)) then
      file = io.open(outputFile, "a")
      file:write(reportwrite, "\n")
    end
  end
  if flag then
    return result
  end
end
