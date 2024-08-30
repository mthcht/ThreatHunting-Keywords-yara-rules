rule Hak5_Cloud_C2
{
    meta:
        description = "Detection patterns for the tool 'Hak5 Cloud C2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hak5 Cloud C2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Hak5 Cloud C2 web title
        // Reference: https://shop.hak5.org/products/c2
        $string1 = /Hak5\sCloud\sC\?/ nocase ascii wide

    condition:
        any of them
}
