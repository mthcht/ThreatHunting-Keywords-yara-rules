rule Jatayu
{
    meta:
        description = "Detection patterns for the tool 'Jatayu' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Jatayu"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Stealthy Stand Alone PHP Web Shell
        // Reference: https://github.com/SpiderMate/Jatayu
        $string1 = /.{0,1000}\/SpiderMate\/Jatayu.{0,1000}/ nocase ascii wide
        // Description: Stealthy Stand Alone PHP Web Shell
        // Reference: https://github.com/SpiderMate/Jatayu
        $string2 = /.{0,1000}bb3b1a1f\-0447\-42a6\-955a\-88681fb88499.{0,1000}/ nocase ascii wide
        // Description: Stealthy Stand Alone PHP Web Shell
        // Reference: https://github.com/SpiderMate/Jatayu
        $string3 = /.{0,1000}jatayu\.php.{0,1000}/ nocase ascii wide
        // Description: Stealthy Stand Alone PHP Web Shell
        // Reference: https://github.com/SpiderMate/Jatayu
        $string4 = /.{0,1000}jatayu\-image\.png.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
