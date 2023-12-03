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
        $string1 = /.{0,1000}\/awesome\-burp\-extensions\/.{0,1000}/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string2 = /.{0,1000}\/burp\/releases\/community\/latest.{0,1000}/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string3 = /.{0,1000}\/burp\-api\/.{0,1000}/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string4 = /.{0,1000}\/BurpExtender\.java.{0,1000}/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string5 = /.{0,1000}\/BurpSuite\-collections.{0,1000}/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string6 = /.{0,1000}\/co2\-cewler\/.{0,1000}/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string7 = /.{0,1000}\/co2\-core\/.{0,1000}/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string8 = /.{0,1000}\/co2\-laudanum\/.{0,1000}/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string9 = /.{0,1000}\/co2\-sqlmapper\/.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts to extend Burp Suite
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string10 = /.{0,1000}\/laconicwolf\/burp\-extensions.{0,1000}/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string11 = /.{0,1000}Burp\sSuite.{0,1000}/ nocase ascii wide
        // Description: PayloadParser - Burp Suite NMap Parsing Interface in Python
        // Reference: https://github.com/infodel/burp.extension-payloadparser
        $string12 = /.{0,1000}burp.{0,1000}PayloadParser\.py.{0,1000}/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string13 = /.{0,1000}burp.{0,1000}SQLMapper\.xml.{0,1000}/ nocase ascii wide
        // Description: PayloadParser - Burp Suite NMap Parsing Interface in Python
        // Reference: https://github.com/infodel/burp.extension-payloadparser
        $string14 = /.{0,1000}burp\.extension\-payloadparser.{0,1000}/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string15 = /.{0,1000}Burp_start\.bat.{0,1000}/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string16 = /.{0,1000}Burp_start_en\.bat.{0,1000}/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string17 = /.{0,1000}burp\-co2\/out\/artifacts.{0,1000}/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string18 = /.{0,1000}BurpCO2Suite\.xml.{0,1000}/ nocase ascii wide
        // Description: Burp Suite is a leading range of cybersecurity tools. brought to you by PortSwigger. We believe in giving our users a competitive advantage through superior research. This tool is not free and open source
        // Reference: https://portswigger.net/burp
        $string19 = /.{0,1000}burpcollaborator\.net.{0,1000}/ nocase ascii wide
        // Description: A Burp Suite extension to help pentesters to bypass WAFs or test their effectiveness using a number of techniques
        // Reference: https://github.com/nccgroup/BurpSuiteHTTPSmuggler
        $string20 = /.{0,1000}BurpFunctions\.java.{0,1000}/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string21 = /.{0,1000}BurpShiroPassiveScan\.jar.{0,1000}/ nocase ascii wide
        // Description: Burp Suite is a leading range of cybersecurity tools. brought to you by PortSwigger. We believe in giving our users a competitive advantage through superior research. This tool is not free and open source
        // Reference: https://portswigger.net/burp
        $string22 = /.{0,1000}Burpsuite.{0,1000}/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string23 = /.{0,1000}burpsuite.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string24 = /.{0,1000}burpsuite.{0,1000}\.jar.{0,1000}/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string25 = /.{0,1000}burpsuite.{0,1000}\.sh.{0,1000}/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string26 = /.{0,1000}burpsuite.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string27 = /.{0,1000}BurpSuiteCn\.jar.{0,1000}/ nocase ascii wide
        // Description: A Burp Suite extension to help pentesters to bypass WAFs or test their effectiveness using a number of techniques
        // Reference: https://github.com/nccgroup/BurpSuiteHTTPSmuggler
        $string28 = /.{0,1000}BurpSuiteHTTPSmuggler.{0,1000}/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string29 = /.{0,1000}burp\-vulners\-scanner\-.{0,1000}\.jar.{0,1000}/ nocase ascii wide
        // Description: find several bugbounty-worthy XSSes. OpenRedirects and SQLi.
        // Reference: https://github.com/attackercan/burp-xss-sql-plugin
        $string30 = /.{0,1000}burp\-xss\-sql\-plugin.{0,1000}/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string31 = /.{0,1000}bypasswaf\.jar.{0,1000}/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string32 = /.{0,1000}captcha\-killer\..{0,1000}\.jar.{0,1000}/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string33 = /.{0,1000}CN\=PortSwigger.{0,1000}/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string34 = /.{0,1000}domain_hunter\-v.{0,1000}\.jar/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string35 = /.{0,1000}FastjsonScan\.jar.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts to extend Burp Suite
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string36 = /.{0,1000}GenerateForcedBrowseWordlist\.py.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts to extend Burp SuiteExtracts the parameters from URLs in scope or from a selected host
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string37 = /.{0,1000}GenerateParameterWordlist\.py.{0,1000}/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string38 = /.{0,1000}http\-request\-smuggler\-all\.jar.{0,1000}/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string39 = /.{0,1000}httpsmuggler\.jar.{0,1000}/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string40 = /.{0,1000}IBurpExtender\.java.{0,1000}/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string41 = /.{0,1000}IBurpExtenderCallbacks\.java.{0,1000}/ nocase ascii wide
        // Description: Multi-tabbed extension that helps generate payloads for various purposes (XSS. SQLi. Header injection. and more).
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string42 = /.{0,1000}InjectMate\.py.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts to extend Burp Suite
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string43 = /.{0,1000}InjectMateCommunity\.py.{0,1000}/ nocase ascii wide
        // Description: CO2 is a project for lightweight and useful enhancements to Portswigger popular Burp Suite web penetration tool through the standard Extender API
        // Reference: https://github.com/JGillam/burp-co2
        $string44 = /.{0,1000}JGillam\/burp\-co2.{0,1000}/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string45 = /.{0,1000}LFI\sscanner\schecks\.jar.{0,1000}/ nocase ascii wide
        // Description: A Burp Suite extension to help pentesters to bypass WAFs or test their effectiveness using a number of techniques
        // Reference: https://github.com/nccgroup/BurpSuiteHTTPSmuggler
        $string46 = /.{0,1000}MakeHTTPSmugglerJAR\.launch.{0,1000}/ nocase ascii wide
        // Description: The class-leading vulnerability scanning. penetration testing. and web app security platform
        // Reference: https://portswigger.net/burp
        $string47 = /.{0,1000}perfdata\.portswigger\.net.{0,1000}/ nocase ascii wide
        // Description: Burp Suite is a leading range of cybersecurity tools. brought to you by PortSwigger. We believe in giving our users a competitive advantage through superior research. This tool is not free and open source
        // Reference: https://portswigger.net/
        $string48 = /.{0,1000}portswigger\.net.{0,1000}/ nocase ascii wide
        // Description: Burp Suite is a leading range of cybersecurity tools. brought to you by PortSwigger. We believe in giving our users a competitive advantage through superior research. This tool is not free and open source
        // Reference: https://portswigger.net/burp
        $string49 = /.{0,1000}portswigger\.net.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts to extend Burp Suite. the request gets transformed to its equivalent in Python requests. Python urllib2. and PowerShell Invoke-WebRequest.
        // Reference: https://github.com/laconicwolf/burp-extensions
        $string50 = /.{0,1000}RequestAsPython\-PowerShell\.py.{0,1000}/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string51 = /.{0,1000}sqlmap4burp.{0,1000}\.jar.{0,1000}/ nocase ascii wide
        // Description: Red Team Toolkit is an Open-Source Django Offensive Web-App which is keeping the useful offensive tools used in the red-teaming together
        // Reference: https://github.com/signorrayan/RedTeam_toolkit
        $string52 = /.{0,1000}sshbrute\.py.{0,1000}/ nocase ascii wide
        // Description: Collection of burpsuite plugins
        // Reference: https://github.com/Mr-xn/BurpSuite-collections
        $string53 = /.{0,1000}struts_ext_v2\.jar.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
