rule domained
{
    meta:
        description = "Detection patterns for the tool 'domained' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "domained"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A domain name enumeration tool
        // Reference: https://github.com/TypeError/domained
        $string1 = /TypeError\/domained/ nocase ascii wide

    condition:
        any of them
}
