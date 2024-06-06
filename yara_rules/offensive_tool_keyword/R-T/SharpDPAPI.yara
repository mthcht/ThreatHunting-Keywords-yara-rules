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
        $string1 = /\sbackupkey.{0,1000}\s\/server\:.{0,1000}\s\/file.{0,1000}\.pvk/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string2 = /\sblob\s\/target\:.{0,1000}\.bin.{0,1000}\s\/pvk\:/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string3 = /\sblob\s\/target\:.{0,1000}\.bin.{0,1000}\s\/unprotect/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string4 = /\scredentials\s\/pvk\:/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string5 = /\skeepass\s\/unprotect/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string6 = /\sps\s\/target\:.{0,1000}\.xml\s\/unprotect/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string7 = /\svaults\s\/target\:.{0,1000}\s\/pvk\:/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string8 = /\.exe\s\scertificates\s\/pvk\:.{0,1000}\.pvk/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string9 = /\.exe\s\skeepass\s\/unprotect/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string10 = /\.exe\sbackupkey\s\/nowrap\s.{0,1000}\.pvk/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string11 = /\.exe\sbackupkey\s\/server\:/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string12 = /\.exe\sblob\s\/target\:C\:\\Temp\\/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string13 = /\.exe\scertificates\s\/mkfile\:.{0,1000}\.txt/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string14 = /\.exe\scertificates\s\/unprotect/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string15 = /\.exe\scredentials\s\/pvk\:.{0,1000}\.pvk/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string16 = /\.exe\smachinemasterkeys/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string17 = /\.exe\smachinetriage/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string18 = /\.exe\smachinevaults/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string19 = /\.exe\smasterkeys\s\/hashes/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string20 = /\.exe\smasterkeys\s\/hashes/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string21 = /\.exe\smasterkeys\s\/pvk\:/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string22 = /\.exe\sps\s\/target\:C\:\\Temp\\.{0,1000}\s\/unprotect/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string23 = /\.exe\srdg\s\/unprotect/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string24 = /\.exe\striage\s\/password\:/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string25 = /\/SharpDPAPI\.git/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string26 = /\[SharpDPAPI\.Program\]\:\:Main\(\"machinemasterkeys\"\)/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string27 = /\[X\]\sMust\sbe\selevated\sto\striage\sSYSTEM\scredentials\!/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string28 = /\[X\]\sMust\sbe\selevated\sto\striage\sSYSTEM\smasterkeys\!/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string29 = /\[X\]\sMust\sbe\selevated\sto\striage\sSYSTEM\svaults\!/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string30 = /\\Commands\\Machinecredentials\.cs/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string31 = /\\SharpDPAPI\\/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string32 = /\]\sWill\sdecrypt\suser\smasterkeys\swith\sNTLM\shash\:\s/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string33 = /2F00A05B\-263D\-4FCC\-846B\-DA82BD684603/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string34 = /5d975e81c68574849bb0fec4c6d2116a4ba7dd58bdd1710463ab75d9a8054bc3/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string35 = /5F026C27\-F8E6\-4052\-B231\-8451C6A73838/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string36 = /d907d7686b725441db1deb645a7079ca79f4dd1d8a18ca4b2bb98c12622603ef/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string37 = /GhostPack\/SharpDPAPI/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string38 = /MakeMeEnterpriseAdmin\.ps1/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string39 = /SharpChrome.{0,1000}\sbackupkey\s.{0,1000}\.pvk/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string40 = /SharpDPAPI\sbackupkey/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string41 = /SharpDPAPI.{0,1000}\scredentias\s/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string42 = /SharpDPAPI.{0,1000}\svaults\s/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string43 = /SharpDPAPI\.csproj/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string44 = /SharpDPAPI\.Domain/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string45 = /SharpDPAPI\.exe/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string46 = /SharpDPAPI\.Helpers\./ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string47 = /SharpDPAPI\.ps1/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string48 = /SharpDPAPI\.sln/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string49 = /SharpDPAPI\.txt/ nocase ascii wide
        // Description: SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // Reference: https://github.com/GhostPack/SharpDPAPI
        $string50 = /SharpDPAPI\-master/ nocase ascii wide

    condition:
        any of them
}
