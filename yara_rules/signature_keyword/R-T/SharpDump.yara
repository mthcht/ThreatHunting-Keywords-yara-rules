rule SharpDump
{
    meta:
        description = "Detection patterns for the tool 'SharpDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDump"
        rule_category = "signature_keyword"

    strings:
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string1 = "ATK/SharpDump-A" nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string2 = /HackTool\.MSIL\.SharpDump32\.SM/ nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string3 = /Hacktool\.SharpDump/ nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string4 = "HackTool:MSIL/SharpDump" nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string5 = /HEUR\:HackTool\.MSIL\.SharpDump\.gen/ nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string6 = "HTool-GhostPack" nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string7 = /Win\.Tool\.Sharpdump/ nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string8 = /Windows\.Hacktool\.SharpDump/ nocase ascii wide

    condition:
        any of them
}
