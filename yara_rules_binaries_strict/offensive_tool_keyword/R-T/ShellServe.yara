rule ShellServe
{
    meta:
        description = "Detection patterns for the tool 'ShellServe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShellServe"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Multi-client network fileserver with integrated shell functionality crafted in C using system calls for efficient and direct file and command processing
        // Reference: https://github.com/7etsuo/ShellServe
        $string1 = /\/ShellServe\.git/ nocase ascii wide
        // Description: Multi-client network fileserver with integrated shell functionality crafted in C using system calls for efficient and direct file and command processing
        // Reference: https://github.com/7etsuo/ShellServe
        $string2 = "@author 7etsuo" nocase ascii wide
        // Description: Multi-client network fileserver with integrated shell functionality crafted in C using system calls for efficient and direct file and command processing
        // Reference: https://github.com/7etsuo/ShellServe
        $string3 = "7c8c4d1e312218cb8a31c00d67f3b5e2e752d9e094e37c959e35e0483fc69109" nocase ascii wide
        // Description: Multi-client network fileserver with integrated shell functionality crafted in C using system calls for efficient and direct file and command processing
        // Reference: https://github.com/7etsuo/ShellServe
        $string4 = "7etsuo/ShellServe" nocase ascii wide
        // Description: Multi-client network fileserver with integrated shell functionality crafted in C using system calls for efficient and direct file and command processing
        // Reference: https://github.com/7etsuo/ShellServe
        $string5 = "d1f5e8ada7197e67b7bdede4827104e286c63f24407bb9eef80cc7c2bd2e065f" nocase ascii wide
        // Description: Multi-client network fileserver with integrated shell functionality crafted in C using system calls for efficient and direct file and command processing
        // Reference: https://github.com/7etsuo/ShellServe
        $string6 = "edaa2e28eee643e72776396155001db13f288d9bc64e57057127a09c1d57c9a7" nocase ascii wide
        // Description: Multi-client network fileserver with integrated shell functionality crafted in C using system calls for efficient and direct file and command processing
        // Reference: https://github.com/7etsuo/ShellServe
        $string7 = /load_credentials\(\\"credentials\.txt\\"\)/ nocase ascii wide
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
