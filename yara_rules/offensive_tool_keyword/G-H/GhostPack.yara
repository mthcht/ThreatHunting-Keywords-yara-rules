rule GhostPack
{
    meta:
        description = "Detection patterns for the tool 'GhostPack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GhostPack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A collection of security related toolsets.with known hacktools
        // Reference: https://github.com/GhostPack
        $string1 = /GhostPack/ nocase ascii wide

    condition:
        any of them
}
