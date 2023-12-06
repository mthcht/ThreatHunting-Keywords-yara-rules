rule AggressorScripts_1
{
    meta:
        description = "Detection patterns for the tool 'AggressorScripts-1' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AggressorScripts-1"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Collection of Aggressor scripts for Cobalt Strike 3.0+ pulled from multiple sources
        // Reference: https://github.com/Cn33liz/AggressorScripts-1
        $string1 = /AggressorScripts/ nocase ascii wide
        // Description: persistence script for cobaltstrike. Persistence Aggressor Scripts for Cobalt Strike 3.0+
        // Reference: https://github.com/Cn33liz/AggressorScripts-1/tree/master/Persistence
        $string2 = /Persist\.cna/ nocase ascii wide

    condition:
        any of them
}
