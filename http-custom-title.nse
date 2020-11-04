local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Shows the title of the default page of a web server. 
If customtitle argument is give the script searches and only titles matching the provided argument. 
The script also writes matched output if outputfile argument is provided.

The script will follow up to 5 HTTP redirects, using the default rules in the
http library.
]]


---nmap --script ./http-custom-title.nse -p80 scanme.nmap.org  --script-args="customtitle='ScanMe'"
--@args http-custom-title.url The url to fetch. Default: /
--@args http-custom-title.output, The output file to write to. 
--@args http-custom-title.customtitle, The title to search for. 
--@output
-- Nmap scan report for scanme.nmap.org (45.33.32.156)
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-title: Go ahead and ScanMe!
--
-- @xmloutput
-- <elem key="title">Go ahead and ScanMe!</elem>
-- @xmloutput
-- <script id="http-custom-title" output="Go ahead and ScanMe!"></script></port>
--

author = "Modified script by @psc4re for custom title search. Original script by Diman Todorov http-title.nse"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}


portrule = shortport.http

action = function(host, port)
  local resp, redirect_url, title
  local reportwrite
  resp = http.get( host, port, stdnse.get_script_args(SCRIPT_NAME..".url") or "/" )
  local outputFile = stdnse.get_script_args(SCRIPT_NAME..".output") or nil
  local customtitle = stdnse.get_script_args(SCRIPT_NAME..".customtitle") or nil
  local output_str = nil 

  -- check for a redirect
  if resp.location then
    redirect_url = resp.location[#resp.location]
    if resp.status and tostring( resp.status ):match( "30%d" ) then
      return {redirect_url = redirect_url}, ("Did not follow redirect to %s"):format( redirect_url )
    end
  end

  if ( not(resp.body) ) then
    return
  end

  -- try and match title tags
  title = string.match(resp.body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]*)</[Tt][Ii][Tt][Ll][Ee]>")

  local display_title = title

  if display_title and display_title ~= "" then
    display_title = string.gsub(display_title , "[\n\r\t]", "")
    if #display_title > 65 then
      display_title = string.sub(display_title, 1, 62) .. "..."
    end
  else
    display_title = "Site doesn't have a title"
    if ( resp.header and resp.header["content-type"] ) then
      display_title = display_title .. (" (%s)."):format( resp.header["content-type"] )
    else
      display_title = display_title .. "."
    end
  end

  local output_tab = stdnse.output_table()
  if  not customtitle then
    reportwrite = "" .. host.ip .. ";" .. display_title
    output_str = display_title
  else   
    if (string.match(display_title, customtitle)) then
      reportwrite = "" .. host.ip .. ";" .. display_title
      output_str = display_title      
    end
  end
  if (outputFile) then
    print("eh,k")
    file = io.open(outputFile, "a")
    file:write(reportwrite, "\n")
    file.close(file)
  end
  if output_str then 
    return output_tab, output_str 
  end
end
