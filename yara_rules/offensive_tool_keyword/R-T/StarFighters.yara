rule StarFighters
{
    meta:
        description = "Detection patterns for the tool 'StarFighters' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "StarFighters"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A JavaScript and VBScript Based Empire Launcher - by Cn33liz 2017
        // Reference: https://github.com/Cn33liz/StarFighters
        $string1 = /StarFighters/ nocase ascii wide

    condition:
        any of them
}
