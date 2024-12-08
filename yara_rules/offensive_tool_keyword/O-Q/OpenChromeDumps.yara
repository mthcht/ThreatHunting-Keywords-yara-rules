rule OpenChromeDumps
{
    meta:
        description = "Detection patterns for the tool 'OpenChromeDumps' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OpenChromeDumps"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: OpenChrome Dump used with GrabChrome for credential access
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string1 = /\\openchromedumps\.exe/ nocase ascii wide
        // Description: OpenChrome Dump used with GrabChrome for credential access
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string2 = /\\openChromeDumps\.pdb/ nocase ascii wide
        // Description: OpenChrome Dump used with GrabChrome for credential access
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string3 = "0b9219328ebf065db9b26c9a189d72c7d0d9c39eb35e9fd2a5fefa54a7f853e4" nocase ascii wide
        // Description: OpenChrome Dump used with GrabChrome for credential access
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string4 = "1c543ea5c50ef8b0b42f835970fa5f553c2ae5c308d2692b51fb476173653cb3" nocase ascii wide
        // Description: OpenChrome Dump used with GrabChrome for credential access
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string5 = "99e25d4179b7a0419d07f671ab86f25a86582e256e0862fc431eb7f93cfb3ced" nocase ascii wide
        // Description: OpenChrome Dump used with GrabChrome for credential access
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string6 = /openChromeDumpsHTML\.exe/ nocase ascii wide

    condition:
        any of them
}
