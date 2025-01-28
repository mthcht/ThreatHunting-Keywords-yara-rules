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
        $string1 = " install autobloody"
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string2 = /\/autobloody\.git/
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string3 = "/autobloody/archive"
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string4 = "AD Privesc Automation"
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string5 = "autobloody -"
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string6 = /autobloody\.py/
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string7 = "autobloody-main"
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string8 = "bolt://localhost:7687"
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string9 = "CravateRouge/autobloody"
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string10 = "Proxy bypass enabled for Neo4j connection"
        // Description: Tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound
        // Reference: https://github.com/CravateRouge/autobloody
        $string11 = /proxy_bypass\.py/

    condition:
        any of them
}
