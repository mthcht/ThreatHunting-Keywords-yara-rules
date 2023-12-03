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
        $string1 = /.{0,1000}\s\-dc\-host\s.{0,1000}\s\-spn\s.{0,1000}\s\-impersonate\s.{0,1000}/ nocase ascii wide
        // Description: Python implementation for CVE-2021-42278 (Active Directory Privilege Escalation)
        // Reference: https://github.com/ly4k/Pachine
        $string2 = /.{0,1000}\.\/pachine\.py.{0,1000}/ nocase ascii wide
        // Description: Python implementation for CVE-2021-42278 (Active Directory Privilege Escalation)
        // Reference: https://github.com/ly4k/Pachine
        $string3 = /.{0,1000}\/ly4k\/Pachine.{0,1000}/ nocase ascii wide
        // Description: Python implementation for CVE-2021-42278 (Active Directory Privilege Escalation)
        // Reference: https://github.com/ly4k/Pachine
        $string4 = /.{0,1000}python.{0,1000}\spachine\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
