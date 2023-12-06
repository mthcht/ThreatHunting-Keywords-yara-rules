rule Pachine
{
    meta:
        description = "Detection patterns for the tool 'Pachine' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pachine"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Python implementation for CVE-2021-42278 (Active Directory Privilege Escalation)
        // Reference: https://github.com/ly4k/Pachine
        $string1 = /\s\-dc\-host\s.{0,1000}\s\-spn\s.{0,1000}\s\-impersonate\s/ nocase ascii wide
        // Description: Python implementation for CVE-2021-42278 (Active Directory Privilege Escalation)
        // Reference: https://github.com/ly4k/Pachine
        $string2 = /\.\/pachine\.py/ nocase ascii wide
        // Description: Python implementation for CVE-2021-42278 (Active Directory Privilege Escalation)
        // Reference: https://github.com/ly4k/Pachine
        $string3 = /\/ly4k\/Pachine/ nocase ascii wide
        // Description: Python implementation for CVE-2021-42278 (Active Directory Privilege Escalation)
        // Reference: https://github.com/ly4k/Pachine
        $string4 = /python.{0,1000}\spachine\.py/ nocase ascii wide

    condition:
        any of them
}
