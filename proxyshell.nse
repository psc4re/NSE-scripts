local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Script by @psc4re for checking against Outlook Exchange Server ProxyShell Vulnerability CVE-2021-34473
Credits: https://twitter.com/bad_packets/status/1426968952278708225 & https://github.com/dinosn/proxyshell for packet info  
]]


-- @usage
-- nmap --script proxyshell.nse -p443 <host> 
--
-- @output
-- | proxyshell:
-- |_  Exchange ProxyShell: Vulnerable to ProxyShell Vulnerability CVE-2021-34473!
----------------------------------------------------------

author = "psc4re"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
portrule = shortport.http

local function getVulnStatus(host, port)
    testpayload = "/autodiscover/autodiscover.json?@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com"
    httpresp = http.get(host, port, testpayload)
    if(httpresp['status'] == 302 ) then
        return "Vulnerable to ProxyShell Vulnerability CVE-2021-34473!"
    end
end


action = function(host, port)
    local resp = http.get(host, port, "/owa")
    local response = stdnse.output_table()
    if resp.status == 200 then
        response["Exchange ProxyShell"] = getVulnStatus(host, port)
    end
    return response
end
