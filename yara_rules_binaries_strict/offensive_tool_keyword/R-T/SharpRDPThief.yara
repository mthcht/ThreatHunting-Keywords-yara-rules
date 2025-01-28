rule SharpRDPThief
{
    meta:
        description = "Detection patterns for the tool 'SharpRDPThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpRDPThief"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A C# implementation of RDPThief to steal credentials from RDP
        // Reference: https://github.com/passthehashbrowns/SharpRDPThief
        $string1 = /\sRDPHook\.dll/ nocase ascii wide
        // Description: A C# implementation of RDPThief to steal credentials from RDP
        // Reference: https://github.com/passthehashbrowns/SharpRDPThief
        $string2 = /\/RDPHook\.dll/ nocase ascii wide
        // Description: A C# implementation of RDPThief to steal credentials from RDP
        // Reference: https://github.com/passthehashbrowns/SharpRDPThief
        $string3 = /\/SharpRDPThief\.git/ nocase ascii wide
        // Description: A C# implementation of RDPThief to steal credentials from RDP
        // Reference: https://github.com/passthehashbrowns/SharpRDPThief
        $string4 = /\\RDPHook\.dll/ nocase ascii wide
        // Description: A C# implementation of RDPThief to steal credentials from RDP
        // Reference: https://github.com/passthehashbrowns/SharpRDPThief
        $string5 = /\\SharpRDPThief\\/ nocase ascii wide
        // Description: A C# implementation of RDPThief to steal credentials from RDP
        // Reference: https://github.com/passthehashbrowns/SharpRDPThief
        $string6 = "20B3AA84-9CA7-43E5-B0CD-8DBA5091DF92" nocase ascii wide
        // Description: A C# implementation of RDPThief to steal credentials from RDP
        // Reference: https://github.com/passthehashbrowns/SharpRDPThief
        $string7 = "73B2C22B-C020-45B7-BF61-B48F49A2693F" nocase ascii wide
        // Description: A C# implementation of RDPThief to steal credentials from RDP
        // Reference: https://github.com/passthehashbrowns/SharpRDPThief
        $string8 = "bbfe2aee2092d981bd2822b8fde8db0ed264f0f86ed445d8987d99b505fd0ff5" nocase ascii wide
        // Description: A C# implementation of RDPThief to steal credentials from RDP
        // Reference: https://github.com/passthehashbrowns/SharpRDPThief
        $string9 = "FileMonitor has injected FileMonitorHook into process " nocase ascii wide
        // Description: A C# implementation of RDPThief to steal credentials from RDP
        // Reference: https://github.com/passthehashbrowns/SharpRDPThief
        $string10 = /Hook\sinstalled\sin\smstsc\.exe\,\sPID\s/ nocase ascii wide
        // Description: A C# implementation of RDPThief to steal credentials from RDP
        // Reference: https://github.com/passthehashbrowns/SharpRDPThief
        $string11 = "passthehashbrowns/SharpRDPThief" nocase ascii wide
        // Description: A C# implementation of RDPThief to steal credentials from RDP
        // Reference: https://github.com/passthehashbrowns/SharpRDPThief
        $string12 = "SharpRDPThief is a C# implementation of RDPThief" nocase ascii wide
        // Description: A C# implementation of RDPThief to steal credentials from RDP
        // Reference: https://github.com/passthehashbrowns/SharpRDPThief
        $string13 = /SharpRDPThief\.csproj/ nocase ascii wide
        // Description: A C# implementation of RDPThief to steal credentials from RDP
        // Reference: https://github.com/passthehashbrowns/SharpRDPThief
        $string14 = /SharpRDPThief\.exe/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
