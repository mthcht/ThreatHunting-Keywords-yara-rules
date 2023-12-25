rule BabyShark
{
    meta:
        description = "Detection patterns for the tool 'BabyShark' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BabyShark"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string1 = /\/BabyShark\.git/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string2 = /\/home\/daddyShark\/BabySh4rk\// nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string3 = /\/momyshark\.html/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string4 = /\\BabyShark\-master\.zip/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string5 = /\\sharklog\.log/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string6 = /database\/c2\.db/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string7 = /password\s\=\s\'b4bysh4rk\'/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string8 = /UnkL4b\/BabyShark/ nocase ascii wide

    condition:
        any of them
}
