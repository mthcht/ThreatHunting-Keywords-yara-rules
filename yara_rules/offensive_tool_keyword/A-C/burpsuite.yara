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
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string12 = /\/http\-request\-smuggler\// nocase ascii wide
        // Description: A collection of scripts to extend Burp Suite
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string13 = /\/laconicwolf\/burp\-extensions/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string14 = /\/turbo\-intruder\-all\.jar/ nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string15 = /\\DigitalOceanProxyTab\.java/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string16 = /\\http\-request\-smuggler\\/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string17 = /\\turbo\-intruder\-all\.jar/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string18 = /4955d7e8fc3d3ded8e3b95757c78b3c4cd969b5fbb92a65267e6141b8faa83d5/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string19 = /Burp\sSuite/ nocase ascii wide
        // Description: PayloadParser - Burp Suite NMap Parsing Interface in Python
        // Reference: https://github.com/infodel/burp.extension-payloadparser
        $string20 = /burp.{0,1000}PayloadParser\.py/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string21 = /burp.{0,1000}SQLMapper\.xml/ nocase ascii wide
        // Description: PayloadParser - Burp Suite NMap Parsing Interface in Python
        // Reference: https://github.com/infodel/burp.extension-payloadparser
        $string22 = /burp\.extension\-payloadparser/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string23 = /Burp_start\.bat/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string24 = /Burp_start_en\.bat/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string25 = /burp\-co2\/out\/artifacts/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string26 = /BurpCO2Suite\.xml/ nocase ascii wide
        // Description: Burp Suite is a leading range of cybersecurity tools. brought to you by PortSwigger. We believe in giving our users a competitive advantage through superior research. This tool is not free and open source
        // Reference: https://portswigger.net/burp
        $string27 = /burpcollaborator\.net/ nocase ascii wide
        // Description: A Burp Suite extension to help pentesters to bypass WAFs or test their effectiveness using a number of techniques
        // Reference: https://github.com/nccgroup/BurpSuiteHTTPSmuggler
        $string28 = /BurpFunctions\.java/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string29 = /BurpShiroPassiveScan\.jar/ nocase ascii wide
        // Description: Burp Suite is a leading range of cybersecurity tools. brought to you by PortSwigger. We believe in giving our users a competitive advantage through superior research. This tool is not free and open source
        // Reference: https://portswigger.net/burp
        $string30 = /Burpsuite/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string31 = /burpsuite.{0,1000}\.exe/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string32 = /burpsuite.{0,1000}\.jar/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string33 = /burpsuite.{0,1000}\.sh/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string34 = /burpsuite.{0,1000}\.zip/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string35 = /BurpSuiteCn\.jar/ nocase ascii wide
        // Description: A Burp Suite extension to help pentesters to bypass WAFs or test their effectiveness using a number of techniques
        // Reference: https://github.com/nccgroup/BurpSuiteHTTPSmuggler
        $string36 = /BurpSuiteHTTPSmuggler/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string37 = /burp\-vulners\-scanner\-.{0,1000}\.jar/ nocase ascii wide
        // Description: find several bugbounty-worthy XSSes. OpenRedirects and SQLi.
        // Reference: https://github.com/attackercan/burp-xss-sql-plugin
        $string38 = /burp\-xss\-sql\-plugin/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string39 = /bypasswaf\.jar/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string40 = /captcha\-killer\..{0,1000}\.jar/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string41 = /CN\=PortSwigger/ nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string42 = /Creating\sDigitalOcean\sOVPN\sProxy\stab/ nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string43 = /Destroying\sall\sdroplets/ nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string44 = /digitalocean\-droplet\-openvpn\-all\.jar/ nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string45 = /DigitalOceanProxyTab\$1\.class/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string46 = /domain_hunter\-v.{0,1000}\.jar/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string47 = /FastjsonScan\.jar/ nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string48 = /Generated\srandom\spassword\sfor\ssocks\sproxy\:/ nocase ascii wide
        // Description: A collection of scripts to extend Burp Suite
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string49 = /GenerateForcedBrowseWordlist\.py/ nocase ascii wide
        // Description: A collection of scripts to extend Burp SuiteExtracts the parameters from URLs in scope or from a selected host
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string50 = /GenerateParameterWordlist\.py/ nocase ascii wide
        // Description: domains used by burp collaborator - abused for  payload callback
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string51 = /http\:\/\/.{0,1000}\.oast\.fun\// nocase ascii wide
        // Description: domains used by burp collaborator - abused for  payload callback
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string52 = /http\:\/\/.{0,1000}\.oast\.live\// nocase ascii wide
        // Description: domains used by burp collaborator - abused for  payload callback
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string53 = /http\:\/\/.{0,1000}\.oast\.me\// nocase ascii wide
        // Description: domains used by burp collaborator - abused for  payload callback
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string54 = /http\:\/\/.{0,1000}\.oast\.online\// nocase ascii wide
        // Description: domains used by burp collaborator - abused for  payload callback
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string55 = /http\:\/\/.{0,1000}\.oast\.pro\// nocase ascii wide
        // Description: domains used by burp collaborator - abused for  payload callback
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string56 = /http\:\/\/.{0,1000}\.oast\.site\// nocase ascii wide
        // Description: domains used by burp collaborator - abused for  payload callback
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string57 = /http\:\/\/.{0,1000}\.oastify\.com\// nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string58 = /http\-request\-smuggler\-all\.jar/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string59 = /httpsmuggler\.jar/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string60 = /IBurpExtender\.java/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string61 = /IBurpExtenderCallbacks\.java/ nocase ascii wide
        // Description: Multi-tabbed extension that helps generate payloads for various purposes (XSS. SQLi. Header injection. and more).
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string62 = /InjectMate\.py/ nocase ascii wide
        // Description: A collection of scripts to extend Burp Suite
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string63 = /InjectMateCommunity\.py/ nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string64 = /IntruderPayloadGeneratorFactory\.class/ nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string65 = /IntruderPayloadProcessor\.class/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string66 = /JGillam\/burp\-co2/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string67 = /LFI\sscanner\schecks\.jar/ nocase ascii wide
        // Description: A Burp Suite extension to help pentesters to bypass WAFs or test their effectiveness using a number of techniques
        // Reference: https://github.com/nccgroup/BurpSuiteHTTPSmuggler
        $string68 = /MakeHTTPSmugglerJAR\.launch/ nocase ascii wide
        // Description: A BurpSuite extension to deploy an OpenVPN config file to DigitalOcean and set up a SOCKS proxy to route traffic through it
        // Reference: https://github.com/honoki/burp-digitalocean-openvpn-socks
        $string69 = /OpenVPN\/SOCKS\sextension\sinitialized\./ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string70 = /perfdata\.portswigger\.net/ nocase ascii wide
        // Description: Burp Suite is a leading range of cybersecurity tools. brought to you by PortSwigger. We believe in giving our users a competitive advantage through superior research. This tool is not free and open source
        // Reference: https://portswigger.net/
        $string71 = /portswigger\.net/ nocase ascii wide
        // Description: Burp Suite is a leading range of cybersecurity tools. brought to you by PortSwigger. We believe in giving our users a competitive advantage through superior research. This tool is not free and open source
        // Reference: https://portswigger.net/burp
        $string72 = /portswigger\.net/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string73 = /PortSwigger\/http\-request\-smuggler/ nocase ascii wide
        // Description: A collection of scripts to extend Burp Suite. the request gets transformed to its equivalent in Python requests. Python urllib2. and PowerShell Invoke-WebRequest.
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string74 = /RequestAsPython\-PowerShell\.py/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string75 = /sqlmap4burp.{0,1000}\.jar/ nocase ascii wide
        // Description: Red Team Toolkit is an Open-Source Django Offensive Web-App which is keeping the useful offensive tools used in the red-teaming together
        // Reference: https://github.com/signorrayan/RedTeam_toolkit
        $string76 = /sshbrute\.py/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string77 = /struts_ext_v2\.jar/ nocase ascii wide

    condition:
        any of them
}
