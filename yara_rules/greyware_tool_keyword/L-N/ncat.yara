rule ncat
{
    meta:
        description = "Detection patterns for the tool 'ncat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ncat"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: reverse shell persistence
        // Reference: N/A
        $string1 = /\sncat\s.{0,1000}\s\-e\s\/bin\/bash.{0,1000}\|crontab/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string2 = /ncat\s.{0,1000}\s\-p\s4444/ nocase ascii wide

    condition:
        any of them
}
