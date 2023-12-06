rule SharpRDPHijack
{
    meta:
        description = "Detection patterns for the tool 'SharpRDPHijack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpRDPHijack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string1 = /\sSharpRDPHijack/ nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string2 = /\/SharpRDPHijack/ nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string3 = /\\SharpRDPHijack/ nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string4 = /SharpRDPHijack\.cs/ nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string5 = /SharpRDPHijack\.exe/ nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string6 = /SharpRDPHijack\-master/ nocase ascii wide

    condition:
        any of them
}
