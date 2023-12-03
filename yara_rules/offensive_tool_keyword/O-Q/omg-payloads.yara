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
        $string1 = /.{0,1000}\/omg\-payloads\.git.{0,1000}/ nocase ascii wide
        // Description: Official payload library for the O.MG line of products from Mischief Gadgets
        // Reference: https://github.com/hak5/omg-payloads
        $string2 = /.{0,1000}hak5\/omg\-payloads.{0,1000}/ nocase ascii wide
        // Description: Official payload library for the O.MG line of products from Mischief Gadgets
        // Reference: https://github.com/hak5/omg-payloads
        $string3 = /.{0,1000}omg\-payloads.{0,1000}\/payloads\/.{0,1000}/ nocase ascii wide
        // Description: Official payload library for the O.MG line of products from Mischief Gadgets
        // Reference: https://github.com/hak5/omg-payloads
        $string4 = /.{0,1000}omg\-payloads\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
