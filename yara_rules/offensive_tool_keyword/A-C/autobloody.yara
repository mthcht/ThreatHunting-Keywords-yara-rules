rule autobloody
{
    meta:
        description = "Detection patterns for the tool 'autobloody' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "autobloody"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string1 = /.{0,1000}\sinstall\sautobloody.{0,1000}/ nocase ascii wide
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string2 = /.{0,1000}\/autobloody\.git.{0,1000}/ nocase ascii wide
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string3 = /.{0,1000}\/autobloody\/archive.{0,1000}/ nocase ascii wide
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string4 = /.{0,1000}AD\sPrivesc\sAutomation.{0,1000}/ nocase ascii wide
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string5 = /.{0,1000}autobloody\s\-.{0,1000}/ nocase ascii wide
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string6 = /.{0,1000}autobloody\.py.{0,1000}/ nocase ascii wide
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string7 = /.{0,1000}autobloody\-main.{0,1000}/ nocase ascii wide
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string8 = /.{0,1000}bolt:\/\/localhost:7687.{0,1000}/ nocase ascii wide
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string9 = /.{0,1000}CravateRouge\/autobloody.{0,1000}/ nocase ascii wide
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string10 = /.{0,1000}Proxy\sbypass\senabled\sfor\sNeo4j\sconnection.{0,1000}/ nocase ascii wide
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string11 = /.{0,1000}proxy_bypass\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
