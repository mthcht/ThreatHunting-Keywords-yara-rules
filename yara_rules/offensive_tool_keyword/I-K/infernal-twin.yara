rule infernal_twin
{
    meta:
        description = "Detection patterns for the tool 'infernal-twin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "infernal-twin"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This tool is created to aid the penetration testers in assessing wireless security.
        // Reference: https://github.com/entropy1337/infernal-twin
        $string1 = /1337.{0,1000}infernal\-twin/ nocase ascii wide

    condition:
        any of them
}
