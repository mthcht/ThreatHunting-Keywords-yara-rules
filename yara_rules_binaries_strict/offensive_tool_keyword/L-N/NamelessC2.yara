rule NamelessC2
{
    meta:
        description = "Detection patterns for the tool 'NamelessC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NamelessC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string1 = /\sConvertToShellcode\.py/ nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string2 = /\sNamelessLog\.txt/ nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string3 = /\/ConvertToShellcode\.py/ nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string4 = /\/NamelessC2\.git/ nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string5 = /\/NamelessLog\.txt/
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string6 = /\[\+\]\sNameless\sTerminal/ nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string7 = /\[\+\]\sStarting\sNameless\sServer/ nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string8 = /\\ConvertToShellcode\.py/ nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string9 = /\\NamelessC2\./ nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string10 = /\\NamelessLog\.txt/ nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string11 = "1e6f328bb3ca446969f0cf086b873081a5345b49fbb5f0bac9f7e5077cd74f76" nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string12 = "7925b74698a6b8c9a8c0135a6fca700c610b8f97245b61d2949bc2b78c2f74fc" nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string13 = "fcf42661023c6669ed49ee885c76f3edd3b04dedd6e1489d06aa2595c5ae60cc" nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string14 = "from ShellcodeRDI import " nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string15 = "Halo's Gate and Tartarus' Gate Patch for `syscall` instruction rather than `SSN`" nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string16 = "MIIFFDCCAvwCCQDBhPvYPqGG4jANBgkqhkiG9w0BAQsFADBMMQswCQYDVQQGEwJH" nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string17 = "MIIJQQIBADANBgkqhkiG9w0BAQEFAASCCSswggknAgEAAoICAQDCRidsrTMB3NRW" nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string18 = /NamelessImplant\.dll/ nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string19 = /namelessserver\.com/ nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string20 = "NamelessTerminal <OperatorName> <alive/all>" nocase ascii wide
        // Description: A C2 with all its components written in Rust
        // Reference: https://github.com/trickster0/NamelessC2
        $string21 = "trickster0/NamelessC2" nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
