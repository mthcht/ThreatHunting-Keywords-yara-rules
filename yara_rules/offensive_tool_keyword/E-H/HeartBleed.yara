rule HeartBleed
{
    meta:
        description = "Detection patterns for the tool 'HeartBleed' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HeartBleed"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Heart Bleed scanner 
        // Reference: https://github.com/TechnicalMujeeb/HeartBleed
        $string1 = /HeartBleed/ nocase ascii wide

    condition:
        any of them
}
