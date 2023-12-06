rule Airgeddon
{
    meta:
        description = "Detection patterns for the tool 'Airgeddon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Airgeddon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is a multi-use bash script for Linux systems to audit wireless networks.
        // Reference: https://github.com/v1s1t0r1sh3r3/airgeddon
        $string1 = /Airgeddon/ nocase ascii wide

    condition:
        any of them
}
