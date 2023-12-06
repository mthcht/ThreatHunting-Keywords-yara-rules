rule Cain_and_Abel
{
    meta:
        description = "Detection patterns for the tool 'Cain&Abel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cain&Abel"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Cain & Able exploitation tool file 
        // Reference: https://github.com/undergroundwires/CEH-in-bullet-points/blob/master/chapters/08-sniffing/sniffing-tools.md
        $string1 = /\/cain\.html/ nocase ascii wide

    condition:
        any of them
}
