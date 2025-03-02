rule rmdir
{
    meta:
        description = "Detection patterns for the tool 'rmdir' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rmdir"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: del command used by Anti Forensics Tools
        // Reference: https://github.com/PaulNorman01/Forensia
        $string1 = /rmdir\sC\:\\ProgramData\\Microsoft\\Windows\sDefender\\Quarantine\\Entries\s\/S/ nocase ascii wide
        // Description: del command used by Anti Forensics Tools
        // Reference: https://github.com/PaulNorman01/Forensia
        $string2 = /rmdir\sC\:\\ProgramData\\Microsoft\\Windows\sDefender\\Quarantine\\ResourceData\s\/S/ nocase ascii wide

    condition:
        any of them
}
