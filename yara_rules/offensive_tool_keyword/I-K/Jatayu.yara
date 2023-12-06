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
        $string1 = /\/SpiderMate\/Jatayu/ nocase ascii wide
        // Description: Stealthy Stand Alone PHP Web Shell
        // Reference: https://github.com/SpiderMate/Jatayu
        $string2 = /bb3b1a1f\-0447\-42a6\-955a\-88681fb88499/ nocase ascii wide
        // Description: Stealthy Stand Alone PHP Web Shell
        // Reference: https://github.com/SpiderMate/Jatayu
        $string3 = /jatayu\.php/ nocase ascii wide
        // Description: Stealthy Stand Alone PHP Web Shell
        // Reference: https://github.com/SpiderMate/Jatayu
        $string4 = /jatayu\-image\.png/ nocase ascii wide

    condition:
        any of them
}
