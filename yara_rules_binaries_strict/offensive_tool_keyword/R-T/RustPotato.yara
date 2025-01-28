rule RustPotato
{
    meta:
        description = "Detection patterns for the tool 'RustPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RustPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string1 = " -p 4444 -c powershell" nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string2 = "/pipe/RustPotato" nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string3 = /\/RustPotato\.git/ nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string4 = /\[\-\]\sFailed\sto\sstart\sreverse\sshell/ nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string5 = /\\\\pipe\\\\RustPotato/ nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string6 = /\\pipe\\RustPotato/ nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string7 = /\\RustPotato\-main/ nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string8 = "emdnaia/RustPotato" nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string9 = "f458f32e49cf7c57bd3bd32e9c82217f2faab412155c9e2a7c28d1b1b4848c42" nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string10 = "localhost/pipe/RustPotato" nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string11 = /RustPotato\.exe/ nocase ascii wide
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
