rule mousejack
{
    meta:
        description = "Detection patterns for the tool 'mousejack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mousejack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: MouseJack device discovery and research tools
        // Reference: https://github.com/BastilleResearch/mousejack
        $string1 = /mousejack/ nocase ascii wide

    condition:
        any of them
}
