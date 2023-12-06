rule udmp_parser
{
    meta:
        description = "Detection patterns for the tool 'udmp-parser' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "udmp-parser"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Cross-Platform C++ parser library for Windows user minidumps.
        // Reference: https://github.com/0vercl0k/udmp-parser
        $string1 = /\/udmp\-parser\.git/ nocase ascii wide
        // Description: A Cross-Platform C++ parser library for Windows user minidumps.
        // Reference: https://github.com/0vercl0k/udmp-parser
        $string2 = /0vercl0k\/udmp\-parser/ nocase ascii wide
        // Description: A Cross-Platform C++ parser library for Windows user minidumps.
        // Reference: https://github.com/0vercl0k/udmp-parser
        $string3 = /import\sudmp_parser/ nocase ascii wide
        // Description: A Cross-Platform C++ parser library for Windows user minidumps.
        // Reference: https://github.com/0vercl0k/udmp-parser
        $string4 = /install\sudmp_parser/ nocase ascii wide
        // Description: A Cross-Platform C++ parser library for Windows user minidumps.
        // Reference: https://github.com/0vercl0k/udmp-parser
        $string5 = /parser\.exe\s\-a\s.{0,1000}\.dmp/ nocase ascii wide
        // Description: A Cross-Platform C++ parser library for Windows user minidumps.
        // Reference: https://github.com/0vercl0k/udmp-parser
        $string6 = /parser\.exe\s\-a\s.{0,1000}\.dmp/ nocase ascii wide
        // Description: A Cross-Platform C++ parser library for Windows user minidumps.
        // Reference: https://github.com/0vercl0k/udmp-parser
        $string7 = /udmp\-parser\-main/ nocase ascii wide

    condition:
        any of them
}
