rule morphHTA
{
    meta:
        description = "Detection patterns for the tool 'morphHTA' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "morphHTA"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: morphHTA - Morphing Cobalt Strikes evil.HTA payload generator
        // Reference: https://github.com/vysecurity/morphHTA
        $string1 = /morphHTA/ nocase ascii wide

    condition:
        any of them
}
