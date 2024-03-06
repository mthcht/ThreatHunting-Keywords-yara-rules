rule burpsuite
{
    meta:
        description = "Detection patterns for the tool 'burpsuite' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "burpsuite"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string1 = /\sDigitalOceanProxyTab\.java/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string2 = /\/awesome\-burp\-extensions\// nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string3 = /\/burp\/releases\/community\/latest/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string4 = /\/burp\-api\// nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string5 = /\/BurpExtender\.java/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string6 = /\/BurpSuite\-collections/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string7 = /\/co2\-cewler\// nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string8 = /\/co2\-core\// nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string9 = /\/co2\-laudanum\// nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string10 = /\/co2\-sqlmapper\// nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string11 = /\/DigitalOceanProxyTab\.java/ nocase ascii wide
        // Description: A collection of scripts to extend Burp Suite
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string12 = /\/laconicwolf\/burp\-extensions/ nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string13 = /\\DigitalOceanProxyTab\.java/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string14 = /Burp\sSuite/ nocase ascii wide
        // Description: PayloadParser - Burp Suite NMap Parsing Interface in Python
        // Reference: https://github.com/infodel/burp.extension-payloadparser
        $string15 = /burp.{0,1000}PayloadParser\.py/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string16 = /burp.{0,1000}SQLMapper\.xml/ nocase ascii wide
        // Description: PayloadParser - Burp Suite NMap Parsing Interface in Python
        // Reference: https://github.com/infodel/burp.extension-payloadparser
        $string17 = /burp\.extension\-payloadparser/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string18 = /Burp_start\.bat/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string19 = /Burp_start_en\.bat/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string20 = /burp\-co2\/out\/artifacts/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string21 = /BurpCO2Suite\.xml/ nocase ascii wide
        // Description: Burp Suite is a leading range of cybersecurity tools. brought to you by PortSwigger. We believe in giving our users a competitive advantage through superior research. This tool is not free and open source
        // Reference: https://portswigger.net/burp
        $string22 = /burpcollaborator\.net/ nocase ascii wide
        // Description: A Burp Suite extension to help pentesters to bypass WAFs or test their effectiveness using a number of techniques
        // Reference: https://github.com/nccgroup/BurpSuiteHTTPSmuggler
        $string23 = /BurpFunctions\.java/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string24 = /BurpShiroPassiveScan\.jar/ nocase ascii wide
        // Description: Burp Suite is a leading range of cybersecurity tools. brought to you by PortSwigger. We believe in giving our users a competitive advantage through superior research. This tool is not free and open source
        // Reference: https://portswigger.net/burp
        $string25 = /Burpsuite/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string26 = /burpsuite.{0,1000}\.exe/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string27 = /burpsuite.{0,1000}\.jar/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string28 = /burpsuite.{0,1000}\.sh/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string29 = /burpsuite.{0,1000}\.zip/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string30 = /BurpSuiteCn\.jar/ nocase ascii wide
        // Description: A Burp Suite extension to help pentesters to bypass WAFs or test their effectiveness using a number of techniques
        // Reference: https://github.com/nccgroup/BurpSuiteHTTPSmuggler
        $string31 = /BurpSuiteHTTPSmuggler/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string32 = /burp\-vulners\-scanner\-.{0,1000}\.jar/ nocase ascii wide
        // Description: find several bugbounty-worthy XSSes. OpenRedirects and SQLi.
        // Reference: https://github.com/attackercan/burp-xss-sql-plugin
        $string33 = /burp\-xss\-sql\-plugin/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string34 = /bypasswaf\.jar/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string35 = /captcha\-killer\..{0,1000}\.jar/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string36 = /CN\=PortSwigger/ nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string37 = /Creating\sDigitalOcean\sOVPN\sProxy\stab/ nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string38 = /Destroying\sall\sdroplets/ nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string39 = /digitalocean\-droplet\-openvpn\-all\.jar/ nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string40 = /DigitalOceanProxyTab\$1\.class/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string41 = /domain_hunter\-v.{0,1000}\.jar/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string42 = /FastjsonScan\.jar/ nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string43 = /Generated\srandom\spassword\sfor\ssocks\sproxy\:/ nocase ascii wide
        // Description: A collection of scripts to extend Burp Suite
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string44 = /GenerateForcedBrowseWordlist\.py/ nocase ascii wide
        // Description: A collection of scripts to extend Burp SuiteExtracts the parameters from URLs in scope or from a selected host
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string45 = /GenerateParameterWordlist\.py/ nocase ascii wide
        // Description: domains used by burp collaborator - abused for  payload callback
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string46 = /http\:\/\/.{0,1000}\.oast\.fun\// nocase ascii wide
        // Description: domains used by burp collaborator - abused for  payload callback
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string47 = /http\:\/\/.{0,1000}\.oast\.live\// nocase ascii wide
        // Description: domains used by burp collaborator - abused for  payload callback
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string48 = /http\:\/\/.{0,1000}\.oast\.me\// nocase ascii wide
        // Description: domains used by burp collaborator - abused for  payload callback
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string49 = /http\:\/\/.{0,1000}\.oast\.online\// nocase ascii wide
        // Description: domains used by burp collaborator - abused for  payload callback
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string50 = /http\:\/\/.{0,1000}\.oast\.pro\// nocase ascii wide
        // Description: domains used by burp collaborator - abused for  payload callback
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string51 = /http\:\/\/.{0,1000}\.oast\.site\// nocase ascii wide
        // Description: domains used by burp collaborator - abused for  payload callback
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string52 = /http\:\/\/.{0,1000}\.oastify\.com\// nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string53 = /http\-request\-smuggler\-all\.jar/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string54 = /httpsmuggler\.jar/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string55 = /IBurpExtender\.java/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string56 = /IBurpExtenderCallbacks\.java/ nocase ascii wide
        // Description: Multi-tabbed extension that helps generate payloads for various purposes (XSS. SQLi. Header injection. and more).
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string57 = /InjectMate\.py/ nocase ascii wide
        // Description: A collection of scripts to extend Burp Suite
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string58 = /InjectMateCommunity\.py/ nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string59 = /IntruderPayloadGeneratorFactory\.class/ nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string60 = /IntruderPayloadProcessor\.class/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string61 = /JGillam\/burp\-co2/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string62 = /LFI\sscanner\schecks\.jar/ nocase ascii wide
        // Description: A Burp Suite extension to help pentesters to bypass WAFs or test their effectiveness using a number of techniques
        // Reference: https://github.com/nccgroup/BurpSuiteHTTPSmuggler
        $string63 = /MakeHTTPSmugglerJAR\.launch/ nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string64 = /OpenVPN\/SOCKS\sextension\sinitialized\./ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string65 = /perfdata\.portswigger\.net/ nocase ascii wide
        // Description: Burp Suite is a leading range of cybersecurity tools. brought to you by PortSwigger. We believe in giving our users a competitive advantage through superior research. This tool is not free and open source
        // Reference: https://portswigger.net/
        $string66 = /portswigger\.net/ nocase ascii wide
        // Description: Burp Suite is a leading range of cybersecurity tools. brought to you by PortSwigger. We believe in giving our users a competitive advantage through superior research. This tool is not free and open source
        // Reference: https://portswigger.net/burp
        $string67 = /portswigger\.net/ nocase ascii wide
        // Description: A collection of scripts to extend Burp Suite. the request gets transformed to its equivalent in Python requests. Python urllib2. and PowerShell Invoke-WebRequest.
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string68 = /RequestAsPython\-PowerShell\.py/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string69 = /sqlmap4burp.{0,1000}\.jar/ nocase ascii wide
        // Description: Red Team Toolkit is an Open-Source Django Offensive Web-App which is keeping the useful offensive tools used in the red-teaming together
        // Reference: https://github.com/signorrayan/RedTeam_toolkit
        $string70 = /sshbrute\.py/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string71 = /struts_ext_v2\.jar/ nocase ascii wide

    condition:
        any of them
}
