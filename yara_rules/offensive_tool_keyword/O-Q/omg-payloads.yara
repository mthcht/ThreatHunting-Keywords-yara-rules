rule omg_payloads
{
    meta:
        description = "Detection patterns for the tool 'omg-payloads' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "omg-payloads"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Official payload library for the O.MG line of products from Mischief Gadgets
        // Reference: https://github.com/hak5/omg-payloads
        $string1 = /\/omg\-payloads\.git/ nocase ascii wide
        // Description: Official payload library for the O.MG line of products from Mischief Gadgets
        // Reference: https://github.com/hak5/omg-payloads
        $string2 = /hak5\/omg\-payloads/ nocase ascii wide
        // Description: Official payload library for the O.MG line of products from Mischief Gadgets
        // Reference: https://github.com/hak5/omg-payloads
        $string3 = /omg\-payloads.{0,1000}\/payloads\// nocase ascii wide
        // Description: Official payload library for the O.MG line of products from Mischief Gadgets
        // Reference: https://github.com/hak5/omg-payloads
        $string4 = /omg\-payloads\-master/ nocase ascii wide

    condition:
        any of them
}
