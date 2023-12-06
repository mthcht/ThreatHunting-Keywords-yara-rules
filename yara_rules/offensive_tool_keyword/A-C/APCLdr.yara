rule APCLdr
{
    meta:
        description = "Detection patterns for the tool 'APCLdr' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "APCLdr"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: APCLdr: Payload Loader With Evasion Features
        // Reference: https://github.com/NUL0x4C/APCLdr
        $string1 = /\/APCLdr\./ nocase ascii wide
        // Description: APCLdr: Payload Loader With Evasion Features
        // Reference: https://github.com/NUL0x4C/APCLdr
        $string2 = /\\APCLdr\./ nocase ascii wide
        // Description: APCLdr: Payload Loader With Evasion Features
        // Reference: https://github.com/NUL0x4C/APCLdr
        $string3 = /NUL0x4C\/APCLdr/ nocase ascii wide

    condition:
        any of them
}
