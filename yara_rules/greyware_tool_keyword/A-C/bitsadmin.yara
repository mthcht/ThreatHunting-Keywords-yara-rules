rule bitsadmin
{
    meta:
        description = "Detection patterns for the tool 'bitsadmin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bitsadmin"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: bitsadmin obfuscation observed used by attackers
        // Reference: N/A
        $string1 = /b\^i\^t\^s\^a\^d\^min\^\s\/t\^ra\^n\^s\^f\^e\^r\^\s\^\/\^d\^o\^w\^n\^l\^o\^a\^d/ nocase ascii wide
        // Description: bitsadmin suspicious transfer
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string2 = "bitsadmin /transfer " nocase ascii wide
        // Description: bitsadmin suspicious transfer
        // Reference: N/A
        $string3 = /bitsadmin\s\/transfer\sdebjob\s\/download\s\/priority\snormal\s\\.{0,1000}\\C\$\\Windows\\.{0,1000}\.dll/ nocase ascii wide

    condition:
        any of them
}
