rule setspn
{
    meta:
        description = "Detection patterns for the tool 'setspn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "setspn"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Getting users with SPNs
        // Reference: https://github.com/b401/Wiki/blob/main/Security/Windows/AD/enumeration.md?plain=1
        $string1 = /setspn\.exe\s\-F\s\-Q\s.{0,1000}\// nocase ascii wide
        // Description: Getting users with SPNs
        // Reference: https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/
        $string2 = /setspn\.exe.{0,1000}\s\-T\s.{0,1000}\-Q\scifs\// nocase ascii wide

    condition:
        any of them
}
