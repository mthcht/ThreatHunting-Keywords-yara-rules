rule mimipy
{
    meta:
        description = "Detection patterns for the tool 'mimipy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mimipy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool to dump passwords from various processes memory
        // Reference: https://github.com/n1nj4sec/mimipy
        $string1 = /\smimipenguin\.sh/ nocase ascii wide
        // Description: Tool to dump passwords from various processes memory
        // Reference: https://github.com/n1nj4sec/mimipy
        $string2 = /\smimipy\.py\s/ nocase ascii wide
        // Description: Tool to dump passwords from various processes memory
        // Reference: https://github.com/n1nj4sec/mimipy
        $string3 = /\/mimipenguin\.sh/ nocase ascii wide
        // Description: Tool to dump passwords from various processes memory
        // Reference: https://github.com/n1nj4sec/mimipy
        $string4 = /\/mimipy\.git/ nocase ascii wide
        // Description: Tool to dump passwords from various processes memory
        // Reference: https://github.com/n1nj4sec/mimipy
        $string5 = /47042a24b908274eec6f075245339e4f6058834220e3c2469e235c881d8aa5eb/ nocase ascii wide
        // Description: Tool to dump passwords from various processes memory
        // Reference: https://github.com/n1nj4sec/mimipy
        $string6 = /fc22650b89b63d52f14ec5d17c0ee92b1d897825c6b7eb3db391e18268567d25/ nocase ascii wide
        // Description: Tool to dump passwords from various processes memory
        // Reference: https://github.com/n1nj4sec/mimipy
        $string7 = /loot_mysql_passwords\(/ nocase ascii wide
        // Description: Tool to dump passwords from various processes memory
        // Reference: https://github.com/n1nj4sec/mimipy
        $string8 = /mimipy_loot_passwords/ nocase ascii wide
        // Description: Tool to dump passwords from various processes memory
        // Reference: https://github.com/n1nj4sec/mimipy
        $string9 = /n1nj4sec\/mimipy/ nocase ascii wide

    condition:
        any of them
}
