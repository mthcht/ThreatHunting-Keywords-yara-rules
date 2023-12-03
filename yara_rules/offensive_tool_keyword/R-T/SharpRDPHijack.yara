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
        $string1 = /.{0,1000}\sSharpRDPHijack.{0,1000}/ nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string2 = /.{0,1000}\/SharpRDPHijack.{0,1000}/ nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string3 = /.{0,1000}\\SharpRDPHijack.{0,1000}/ nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string4 = /.{0,1000}SharpRDPHijack\.cs.{0,1000}/ nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string5 = /.{0,1000}SharpRDPHijack\.exe.{0,1000}/ nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string6 = /.{0,1000}SharpRDPHijack\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
