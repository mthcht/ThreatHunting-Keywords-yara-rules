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
        $string1 = /\/forkatz\.filters/ nocase ascii wide
        // Description: credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege
        // Reference: https://github.com/Barbarisch/forkatz
        $string2 = /\/forkatz\.git/ nocase ascii wide
        // Description: credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege
        // Reference: https://github.com/Barbarisch/forkatz
        $string3 = /forkatz\.exe/ nocase ascii wide
        // Description: credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege
        // Reference: https://github.com/Barbarisch/forkatz
        $string4 = /forkatz\.sln/ nocase ascii wide
        // Description: credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege
        // Reference: https://github.com/Barbarisch/forkatz
        $string5 = /forkatz\.vcxproj/ nocase ascii wide
        // Description: credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege
        // Reference: https://github.com/Barbarisch/forkatz
        $string6 = /forkatz\-main/ nocase ascii wide
        // Description: credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege
        // Reference: https://github.com/Barbarisch/forkatz
        $string7 = /users\\public\\example\.bin/ nocase ascii wide
        // Description: credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege
        // Reference: https://github.com/Barbarisch/forkatz
        $string8 = /users\\public\\temp\.bin/ nocase ascii wide

    condition:
        any of them
}
