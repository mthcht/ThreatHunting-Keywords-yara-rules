rule BlockEtw
{
    meta:
        description = "Detection patterns for the tool 'BlockEtw' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlockEtw"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string1 = /\/blocketw\.bin/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string2 = /\/blocketw\.exe/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string3 = /\/BlockEtw\.git/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string4 = "/BlockEtw/tarball/" nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string5 = "/BlockEtw/zipball/" nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string6 = /\/opt\/shellcode\/blocketw\.bin/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string7 = /\\blocketw\.bin/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string8 = /\\blocketw\.csproj/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string9 = /\\blocketw\.exe/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string10 = /\\blocketw\.pdb/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string11 = /\\blocketw\.sln/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string12 = /\\BlockEtw\-master/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string13 = /\\Derek\.Admin\.STANNCENTER\\Source\\Repos\\/ nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string14 = ">blocketw<" nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string15 = "0e313d439e080ae59303f87afe484717dab784c8df5f83dcd2745b51194582a8" nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string16 = "0e313d439e080ae59303f87afe484717dab784c8df5f83dcd2745b51194582a8" nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string17 = "55d70f97e0f0c76b7a6ed08178f83ccd5505e8c62213d1fdf5221bc60cf3ffe0" nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string18 = "8904000180688b0ba69b2bc6647fc42c34ed9fce15ed7687d53958f9f9ac6357" nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string19 = "a5034ebb8d6c31c71947c4f85a505f66fd1aadc71cecedd96f1bd02b3e471f62" nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string20 = "a5034ebb8d6c31c71947c4f85a505f66fd1aadc71cecedd96f1bd02b3e471f62" nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string21 = "cb287d756b38831a47d5cd86e5b332be4997d89fa275de5a99883ec151b4bbdc" nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string22 = "cdbf8f32f74fdb65c2a34bfbf7208e24f0c9cc058d76fed96289964fcff50e2a" nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string23 = "DAEDF7B3-8262-4892-ADC4-425DD5F85BCA" nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string24 = "f94889e1ba519e9e4e4e7bbee99f29ee46ab218b45d3a1b49549deba41f083ff" nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string25 = "Soledge/BlockEtw" nocase ascii wide
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
