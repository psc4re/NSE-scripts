
# Contains Custom NSE scripts 


# CVE-2020-0796
NSE script to detect vulnerable CVE-2020-0796 issue, with Microsoft SMBv3 Compression (aka coronablue, SMBGhost)

The script is a modified version of smb-protocols.nse script with a modified output data for v3.11 detection and validating CVE-2020-0796. 

Note: This script just safe checks for CVE-2020-0796 vulnerability on SMBv3 and doesn't attempt anything beyond that.


# Installation and running

Copy the .nse file to nmap/scripts/ folder and run update

``cp cve-2020-0796.nse /usr/share/nmap/scripts/``

``nmap --script-updatedb``

Run as 

``nmap -p445 --script cve-2020-0796 <<target>>``


``-- @output``\
``-- | smb-protocols:``\
``-- |   dialects:``\
``-- |     NT LM 0.12 (SMBv1) [dangerous, but default]``\
``-- |     2.02``\
``-- |     2.10``\
``-- |     3.00``\
``-- |     3.02``\
``-- |_    3.11 (SMBv3.11) LZNT1 compression algorithm - Vulnerable to CVE-2020-0796 SMBGhost``



Checks for compression based on https://github.com/ollypwn/SMBGhost/ Could've been done utilizing smb.lua in the nselib but it required substantial editing of the functions, went with sockets. 



# CVE-2020-1350
NSE script to detect vulnerable CVE-2020-1350 issue, with Microsoft DNS server (aka SIGRed)

The script utilizes code components of dns-nsid.nse script with checks for CVE-2020-1350 

Note: This script just safe checks for CVE-2020-1350  vulnerability on Microsoft DNS Servers for identification purposes only and doesn't attempt anything beyond that. This script is not perfect and depends on the output of dig CH TXT bind.version @target and fails when DNS version number is hidden 


# Installation and running

Copy the .nse file to nmap/scripts/ folder and run update

``cp cve-2020-1350.nse /usr/share/nmap/scripts/``

``nmap --script-updatedb``

Run as 

``sudo nmap -sSU -p53 --script cve-2020-1350 <<target>> ``

 ``sudo nmap -sSU -p53 --script cve-2020-1350 <<target>> --script-args output=<outputfile.txt>``


# http-custom-title

NSE Script to search for custom HTTP titles provided as script arguments. This script helps in searching and providing only results of HTTP titles required. 

# Installation and running

Copy the .nse file to nmap/scripts/ folder and run update

``cp http-custom-title.nse /usr/share/nmap/scripts/``

``nmap --script-updatedb``

Run as 

``nmap --script ./http-custom-title.nse -p80 scanme.nmap.org  --script-args customtitle='ScanMe'``

``nmap --script ./http-custom-title.nse <<target>>  --script-args customtitle='Apache'``


# vCenter RCE CVE-2021-21972 check

For checking against CVE-2021-21972, CVE-2021-21973 Vulnerability in vCenter. The script also additionally prints the vSphere Version and Build Number

Copy the .nse file to nmap/scripts/ folder and run update

``cp cve-2021-21972.nse /usr/share/nmap/scripts/``

``nmap --script-updatedb``

Run as 

``nmap --script cve-2021-21972.nse -p443 <host> (optional: --script-args output=report.txt)``


