rule WinPwnage
{
    meta:
        description = "Detection patterns for the tool 'WinPwnage' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WinPwnage"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string1 = /WinPwnage/ nocase ascii wide

    condition:
        any of them
}
