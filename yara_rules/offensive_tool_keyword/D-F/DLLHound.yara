rule DLLHound
{
    meta:
        description = "Detection patterns for the tool 'DLLHound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DLLHound"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Find potential DLL Sideloads on your windows computer
        // Reference: https://github.com/ajm4n/DLLHound
        $string1 = /\sDLLHound\.ps1/ nocase ascii wide
        // Description: Find potential DLL Sideloads on your windows computer
        // Reference: https://github.com/ajm4n/DLLHound
        $string2 = /\/DLLHound\.git/ nocase ascii wide
        // Description: Find potential DLL Sideloads on your windows computer
        // Reference: https://github.com/ajm4n/DLLHound
        $string3 = /\/DLLHound\.ps1/ nocase ascii wide
        // Description: Find potential DLL Sideloads on your windows computer
        // Reference: https://github.com/ajm4n/DLLHound
        $string4 = /\\DLLHound\.ps1/ nocase ascii wide
        // Description: Find potential DLL Sideloads on your windows computer
        // Reference: https://github.com/ajm4n/DLLHound
        $string5 = /\\DLLScan_\$timestamp\.csv/ nocase ascii wide
        // Description: Find potential DLL Sideloads on your windows computer
        // Reference: https://github.com/ajm4n/DLLHound
        $string6 = "ajm4n/DLLHound" nocase ascii wide
        // Description: Find potential DLL Sideloads on your windows computer
        // Reference: https://github.com/ajm4n/DLLHound
        $string7 = "c9fb3bcd19b8d5dc86f3adf90f4953376910e796cddf0e2fdc1ee439be51b8de" nocase ascii wide
        // Description: Find potential DLL Sideloads on your windows computer
        // Reference: https://github.com/ajm4n/DLLHound
        $string8 = "Start-DLLScan " nocase ascii wide
        // Description: Find potential DLL Sideloads on your windows computer
        // Reference: https://github.com/ajm4n/DLLHound
        $string9 = "Starting DLL sideloading vulnerability scan" nocase ascii wide

    condition:
        any of them
}
