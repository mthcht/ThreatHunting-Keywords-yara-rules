rule forkatz
{
    meta:
        description = "Detection patterns for the tool 'forkatz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "forkatz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege
        // Reference: https://github.com/Barbarisch/forkatz
        $string1 = /.{0,1000}\/forkatz\.filters.{0,1000}/ nocase ascii wide
        // Description: credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege
        // Reference: https://github.com/Barbarisch/forkatz
        $string2 = /.{0,1000}\/forkatz\.git.{0,1000}/ nocase ascii wide
        // Description: credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege
        // Reference: https://github.com/Barbarisch/forkatz
        $string3 = /.{0,1000}forkatz\.exe.{0,1000}/ nocase ascii wide
        // Description: credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege
        // Reference: https://github.com/Barbarisch/forkatz
        $string4 = /.{0,1000}forkatz\.sln.{0,1000}/ nocase ascii wide
        // Description: credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege
        // Reference: https://github.com/Barbarisch/forkatz
        $string5 = /.{0,1000}forkatz\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege
        // Reference: https://github.com/Barbarisch/forkatz
        $string6 = /.{0,1000}forkatz\-main.{0,1000}/ nocase ascii wide
        // Description: credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege
        // Reference: https://github.com/Barbarisch/forkatz
        $string7 = /.{0,1000}users\\public\\example\.bin.{0,1000}/ nocase ascii wide
        // Description: credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege
        // Reference: https://github.com/Barbarisch/forkatz
        $string8 = /.{0,1000}users\\public\\temp\.bin.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
