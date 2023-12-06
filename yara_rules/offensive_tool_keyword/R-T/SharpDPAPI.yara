rule SharpDPAPI
{
    meta:
        description = "Detection patterns for the tool 'SharpDPAPI' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDPAPI"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string1 = /\sbackupkey.{0,1000}\s\/server:.{0,1000}\s\/file.{0,1000}\.pvk/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string2 = /\sblob\s\/target:.{0,1000}\.bin.{0,1000}\s\/pvk:/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string3 = /\sblob\s\/target:.{0,1000}\.bin.{0,1000}\s\/unprotect/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string4 = /\scredentials\s\/pvk:/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string5 = /\skeepass\s\/unprotect/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string6 = /\sps\s\/target:.{0,1000}\.xml\s\/unprotect/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string7 = /\svaults\s\/target:.{0,1000}\s\/pvk:/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string8 = /\.exe\s\scertificates\s\/pvk:.{0,1000}\.pvk/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string9 = /\.exe\sbackupkey\s\/nowrap\s.{0,1000}\.pvk/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string10 = /\.exe\scertificates\s\/mkfile:.{0,1000}\.txt/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string11 = /\.exe\scredentials\s\/pvk:.{0,1000}\.pvk/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string12 = /\.exe\smachinetriage/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string13 = /\.exe\smasterkeys\s\/hashes/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string14 = /\.exe\smasterkeys\s\/hashes/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string15 = /\.exe\striage\s\/password:/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string16 = /\/SharpDPAPI\.git/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string17 = /GhostPack\/SharpDPAPI/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string18 = /SharpDPAPI\sbackupkey/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string19 = /SharpDPAPI.{0,1000}\scredentias\s/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string20 = /SharpDPAPI.{0,1000}\svaults\s/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string21 = /SharpDPAPI\.csproj/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string22 = /SharpDPAPI\.Domain/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string23 = /SharpDPAPI\.exe/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string24 = /SharpDPAPI\.ps1/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string25 = /SharpDPAPI\.sln/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string26 = /SharpDPAPI\.txt/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string27 = /SharpDPAPI\-master/ nocase ascii wide

    condition:
        any of them
}
