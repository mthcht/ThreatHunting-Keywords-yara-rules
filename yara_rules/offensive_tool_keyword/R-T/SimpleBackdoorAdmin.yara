rule SimpleBackdoorAdmin
{
    meta:
        description = "Detection patterns for the tool 'SimpleBackdoorAdmin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SimpleBackdoorAdmin"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string1 = /net\slocalgroup\sadministrators\sbackdoor/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string2 = /net\suser\sbackdoor\sPassword123\!/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string3 = /SimpleBackdoorAdmin\.dll/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string4 = /SimpleBackdoorAdmin\.exe/ nocase ascii wide

    condition:
        any of them
}
