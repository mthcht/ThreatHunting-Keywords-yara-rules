rule Pazuzu
{
    meta:
        description = "Detection patterns for the tool 'Pazuzu' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pazuzu"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Pazuzu is a Python script that allows you to embed a binary within a precompiled DLL which uses reflective DLL injection. The goal is that you can run your own binary directly from memory. This can be useful in various scenarios.
        // Reference: https://github.com/BorjaMerino/Pazuzu
        $string1 = /BorjaMerino.{0,1000}Pazuzu/ nocase ascii wide

    condition:
        any of them
}
