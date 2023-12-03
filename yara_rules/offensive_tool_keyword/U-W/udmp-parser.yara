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
        $string1 = /.{0,1000}\/udmp\-parser\.git.{0,1000}/ nocase ascii wide
        // Description: A Cross-Platform C++ parser library for Windows user minidumps.
        // Reference: https://github.com/0vercl0k/udmp-parser
        $string2 = /.{0,1000}0vercl0k\/udmp\-parser.{0,1000}/ nocase ascii wide
        // Description: A Cross-Platform C++ parser library for Windows user minidumps.
        // Reference: https://github.com/0vercl0k/udmp-parser
        $string3 = /.{0,1000}import\sudmp_parser.{0,1000}/ nocase ascii wide
        // Description: A Cross-Platform C++ parser library for Windows user minidumps.
        // Reference: https://github.com/0vercl0k/udmp-parser
        $string4 = /.{0,1000}install\sudmp_parser.{0,1000}/ nocase ascii wide
        // Description: A Cross-Platform C++ parser library for Windows user minidumps.
        // Reference: https://github.com/0vercl0k/udmp-parser
        $string5 = /.{0,1000}parser\.exe\s\-a\s.{0,1000}\.dmp.{0,1000}/ nocase ascii wide
        // Description: A Cross-Platform C++ parser library for Windows user minidumps.
        // Reference: https://github.com/0vercl0k/udmp-parser
        $string6 = /.{0,1000}parser\.exe\s\-a\s.{0,1000}\.dmp.{0,1000}/ nocase ascii wide
        // Description: A Cross-Platform C++ parser library for Windows user minidumps.
        // Reference: https://github.com/0vercl0k/udmp-parser
        $string7 = /.{0,1000}udmp\-parser\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
