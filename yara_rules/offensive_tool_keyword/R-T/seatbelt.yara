rule Seatbelt
{
    meta:
        description = "Detection patterns for the tool 'Seatbelt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Seatbelt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string1 = /\/Seatbelt\.exe/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string2 = /\\Seatbelt\.exe/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string3 = /Seatbelt\.Commands\.Windows/ nocase ascii wide

    condition:
        any of them
}
