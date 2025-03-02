rule del
{
    meta:
        description = "Detection patterns for the tool 'del' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "del"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: del command used by Anti Forensics Tools
        // Reference: https://github.com/PaulNorman01/Forensia
        $string1 = /del\s\/F\s\/Q\s\%APPDATA\%\\Microsoft\\Windows\\Recent\\/ nocase ascii wide
        // Description: del command used by Anti Forensics Tools
        // Reference: https://github.com/PaulNorman01/Forensia
        $string2 = /del\s\/F\s\/Q\s\%APPDATA\%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\/ nocase ascii wide
        // Description: del command used by Anti Forensics Tools
        // Reference: https://github.com/PaulNorman01/Forensia
        $string3 = /del\s\/F\s\/Q\s\%APPDATA\%\\Microsoft\\Windows\\Recent\\CustomDestinations\\/ nocase ascii wide
        // Description: del command used by Anti Forensics Tools
        // Reference: https://github.com/PaulNorman01/Forensia
        $string4 = /del\s\/F\s\/Q\sC\:\\\\Windows\\\\Prefetch\\\\/ nocase ascii wide
        // Description: del command used by Anti Forensics Tools
        // Reference: https://github.com/PaulNorman01/Forensia
        $string5 = /del\s\/F\s\/Q\sC\:\\Windows\\Prefetch\\/ nocase ascii wide
        // Description: del command used by Anti Forensics Tools
        // Reference: https://github.com/PaulNorman01/Forensia
        $string6 = /del\sC\:\\Windows\\AppCompat\\Programs\\RecentFileCache\.bcf/ nocase ascii wide

    condition:
        any of them
}
