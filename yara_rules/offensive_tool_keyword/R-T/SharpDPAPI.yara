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
        $string1 = /.{0,1000}\sbackupkey.{0,1000}\s\/server:.{0,1000}\s\/file.{0,1000}\.pvk.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string2 = /.{0,1000}\sblob\s\/target:.{0,1000}\.bin.{0,1000}\s\/pvk:.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string3 = /.{0,1000}\sblob\s\/target:.{0,1000}\.bin.{0,1000}\s\/unprotect.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string4 = /.{0,1000}\scredentials\s\/pvk:.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string5 = /.{0,1000}\skeepass\s\/unprotect.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string6 = /.{0,1000}\sps\s\/target:.{0,1000}\.xml\s\/unprotect.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string7 = /.{0,1000}\svaults\s\/target:.{0,1000}\s\/pvk:.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string8 = /.{0,1000}\.exe\s\scertificates\s\/pvk:.{0,1000}\.pvk.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string9 = /.{0,1000}\.exe\sbackupkey\s\/nowrap\s.{0,1000}\.pvk.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string10 = /.{0,1000}\.exe\scertificates\s\/mkfile:.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string11 = /.{0,1000}\.exe\scredentials\s\/pvk:.{0,1000}\.pvk.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string12 = /.{0,1000}\.exe\smachinetriage.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string13 = /.{0,1000}\.exe\smasterkeys\s\/hashes.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string14 = /.{0,1000}\.exe\smasterkeys\s\/hashes.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string15 = /.{0,1000}\.exe\striage\s\/password:.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string16 = /.{0,1000}\/SharpDPAPI\.git.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string17 = /.{0,1000}GhostPack\/SharpDPAPI.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string18 = /.{0,1000}SharpDPAPI\sbackupkey.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string19 = /.{0,1000}SharpDPAPI.{0,1000}\scredentias\s.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string20 = /.{0,1000}SharpDPAPI.{0,1000}\svaults\s.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string21 = /.{0,1000}SharpDPAPI\.csproj.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string22 = /.{0,1000}SharpDPAPI\.Domain.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string23 = /.{0,1000}SharpDPAPI\.exe.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string24 = /.{0,1000}SharpDPAPI\.ps1.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string25 = /.{0,1000}SharpDPAPI\.sln.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string26 = /.{0,1000}SharpDPAPI\.txt.{0,1000}/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string27 = /.{0,1000}SharpDPAPI\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
