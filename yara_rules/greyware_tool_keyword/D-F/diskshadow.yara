rule diskshadow
{
    meta:
        description = "Detection patterns for the tool 'diskshadow' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "diskshadow"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: List shadow copies using diskshadow
        // Reference: N/A
        $string1 = /diskshadow\slist\sshadows\sall/ nocase ascii wide

    condition:
        any of them
}
