rule SharpDump
{
    meta:
        description = "Detection patterns for the tool 'SharpDump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string1 = /\/SharpDump\.exe/ nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string2 = /\/SharpDump\.git/ nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string3 = /\[X\]\sNot\sin\shigh\sintegrity\,\sunable\sto\sMiniDump\!/ nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string4 = /\\Out\-Minidump\.ps1/ nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string5 = /\\SharpDump\.csproj/ nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string6 = /\\SharpDump\.exe/ nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string7 = ">SharpDump<" nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string8 = "0a7cf0b0d8f68eec8829dde1d90183087d641547a6c97de021db9a631da99857" nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string9 = "79C9BBA3-A0EA-431C-866C-77004802D8A0" nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string10 = "7adf4cdaa2190d19969e9f2fe6315d586fd5b709466ef2c84379b8b3a595ffc8" nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string11 = "8ef62495d042ae030268ca52d01baece60c79f34d49a113ef5c2322e7041c053" nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string12 = "a829137b318890cb77f6a1ce28ce4dbaa4a39e19ef91b75f4f50dfc2b1a992bf" nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string13 = "GhostPack/SharpDump" nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string14 = "sekurlsa::logonPasswords full" nocase ascii wide
        // Description: SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // Reference: https://github.com/GhostPack/SharpDump
        $string15 = /sekurlsa\:\:minidump\sdebug\.out/ nocase ascii wide
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
