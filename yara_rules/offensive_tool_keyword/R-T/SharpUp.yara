rule SharpUp
{
    meta:
        description = "Detection patterns for the tool 'SharpUp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpUp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string1 = /SharpUp/ nocase ascii wide

    condition:
        any of them
}
