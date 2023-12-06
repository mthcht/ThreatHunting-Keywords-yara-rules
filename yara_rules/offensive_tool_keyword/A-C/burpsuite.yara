rule burpsuite
{
    meta:
        description = "Detection patterns for the tool 'burpsuite' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "burpsuite"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string1 = /\/awesome\-burp\-extensions\// nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string2 = /\/burp\/releases\/community\/latest/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string3 = /\/burp\-api\// nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string4 = /\/BurpExtender\.java/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string5 = /\/BurpSuite\-collections/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string6 = /\/co2\-cewler\// nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string7 = /\/co2\-core\// nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string8 = /\/co2\-laudanum\// nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string9 = /\/co2\-sqlmapper\// nocase ascii wide
        // Description: A collection of scripts to extend Burp Suite
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string10 = /\/laconicwolf\/burp\-extensions/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string11 = /Burp\sSuite/ nocase ascii wide
        // Description: PayloadParser - Burp Suite NMap Parsing Interface in Python
        // Reference: https://github.com/infodel/burp.extension-payloadparser
        $string12 = /burp.{0,1000}PayloadParser\.py/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string13 = /burp.{0,1000}SQLMapper\.xml/ nocase ascii wide
        // Description: PayloadParser - Burp Suite NMap Parsing Interface in Python
        // Reference: https://github.com/infodel/burp.extension-payloadparser
        $string14 = /burp\.extension\-payloadparser/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string15 = /Burp_start\.bat/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string16 = /Burp_start_en\.bat/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string17 = /burp\-co2\/out\/artifacts/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string18 = /BurpCO2Suite\.xml/ nocase ascii wide
        // Description: Burp Suite is a leading range of cybersecurity tools. brought to you by PortSwigger. We believe in giving our users a competitive advantage through superior research. This tool is not free and open source
        // Reference: https://portswigger.net/burp
        $string19 = /burpcollaborator\.net/ nocase ascii wide
        // Description: A Burp Suite extension to help pentesters to bypass WAFs or test their effectiveness using a number of techniques
        // Reference: https://github.com/nccgroup/BurpSuiteHTTPSmuggler
        $string20 = /BurpFunctions\.java/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string21 = /BurpShiroPassiveScan\.jar/ nocase ascii wide
        // Description: Burp Suite is a leading range of cybersecurity tools. brought to you by PortSwigger. We believe in giving our users a competitive advantage through superior research. This tool is not free and open source
        // Reference: https://portswigger.net/burp
        $string22 = /Burpsuite/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string23 = /burpsuite.{0,1000}\.exe/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string24 = /burpsuite.{0,1000}\.jar/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string25 = /burpsuite.{0,1000}\.sh/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string26 = /burpsuite.{0,1000}\.zip/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string27 = /BurpSuiteCn\.jar/ nocase ascii wide
        // Description: A Burp Suite extension to help pentesters to bypass WAFs or test their effectiveness using a number of techniques
        // Reference: https://github.com/nccgroup/BurpSuiteHTTPSmuggler
        $string28 = /BurpSuiteHTTPSmuggler/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string29 = /burp\-vulners\-scanner\-.{0,1000}\.jar/ nocase ascii wide
        // Description: find several bugbounty-worthy XSSes. OpenRedirects and SQLi.
        // Reference: https://github.com/attackercan/burp-xss-sql-plugin
        $string30 = /burp\-xss\-sql\-plugin/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string31 = /bypasswaf\.jar/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string32 = /captcha\-killer\..{0,1000}\.jar/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string33 = /CN\=PortSwigger/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string34 = /domain_hunter\-v.{0,1000}\.jar/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string35 = /FastjsonScan\.jar/ nocase ascii wide
        // Description: A collection of scripts to extend Burp Suite
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string36 = /GenerateForcedBrowseWordlist\.py/ nocase ascii wide
        // Description: A collection of scripts to extend Burp SuiteExtracts the parameters from URLs in scope or from a selected host
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string37 = /GenerateParameterWordlist\.py/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string38 = /http\-request\-smuggler\-all\.jar/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string39 = /httpsmuggler\.jar/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string40 = /IBurpExtender\.java/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string41 = /IBurpExtenderCallbacks\.java/ nocase ascii wide
        // Description: Multi-tabbed extension that helps generate payloads for various purposes (XSS. SQLi. Header injection. and more).
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string42 = /InjectMate\.py/ nocase ascii wide
        // Description: A collection of scripts to extend Burp Suite
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string43 = /InjectMateCommunity\.py/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string44 = /JGillam\/burp\-co2/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string45 = /LFI\sscanner\schecks\.jar/ nocase ascii wide
        // Description: A Burp Suite extension to help pentesters to bypass WAFs or test their effectiveness using a number of techniques
        // Reference: https://github.com/nccgroup/BurpSuiteHTTPSmuggler
        $string46 = /MakeHTTPSmugglerJAR\.launch/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string47 = /perfdata\.portswigger\.net/ nocase ascii wide
        // Description: Burp Suite is a leading range of cybersecurity tools. brought to you by PortSwigger. We believe in giving our users a competitive advantage through superior research. This tool is not free and open source
        // Reference: https://portswigger.net/
        $string48 = /portswigger\.net/ nocase ascii wide
        // Description: Burp Suite is a leading range of cybersecurity tools. brought to you by PortSwigger. We believe in giving our users a competitive advantage through superior research. This tool is not free and open source
        // Reference: https://portswigger.net/burp
        $string49 = /portswigger\.net/ nocase ascii wide
        // Description: A collection of scripts to extend Burp Suite. the request gets transformed to its equivalent in Python requests. Python urllib2. and PowerShell Invoke-WebRequest.
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string50 = /RequestAsPython\-PowerShell\.py/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string51 = /sqlmap4burp.{0,1000}\.jar/ nocase ascii wide
        // Description: Red Team Toolkit is an Open-Source Django Offensive Web-App which is keeping the useful offensive tools used in the red-teaming together
        // Reference: https://github.com/signorrayan/RedTeam_toolkit
        $string52 = /sshbrute\.py/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string53 = /struts_ext_v2\.jar/ nocase ascii wide

    condition:
        any of them
}
