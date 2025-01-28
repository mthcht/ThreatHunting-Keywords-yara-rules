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
        $string1 = "- RDP Session Hijack" nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string2 = " SharpRDPHijack" nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string3 = /\.exe\s\-\-session\=2\s\-\-shadow\s\-\-console/ nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string4 = "/SharpRDPHijack" nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string5 = /\-\\nSharp\sRDP\sHijack\\n\-/ nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string6 = /\\SharpRDPHijack/ nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string7 = "622f3304b381b2f3a99567be78a668e21c1c6a405320da78a2af32addbc29d88" nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string8 = "Benjamin Delpy - RDP Session Tradecraft" nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string9 = /blog\.gentilkiwi\.com\/securite\/vol\-de\-session\-rdp/ nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string10 = "Hijack Remote Desktop session #4 with knowledge of the logged-on user" nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string11 = /https\:\/\/www\.exploit\-db\.com\/exploits\/41607/ nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string12 = /Impersonate\sNT\sAUTHORITY\\\\SYSTEM\sto\shijack\ssession/ nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string13 = /SharpRDPHijack\.cs/ nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string14 = /SharpRDPHijack\.exe/ nocase ascii wide
        // Description: SharpRDPHijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility for disconnected sessions
        // Reference: https://github.com/bohops/SharpRDPHijack
        $string15 = "SharpRDPHijack-master" nocase ascii wide

    condition:
        any of them
}
