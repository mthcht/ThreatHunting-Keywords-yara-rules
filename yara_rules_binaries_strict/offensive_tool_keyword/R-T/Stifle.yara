rule Stifle
{
    meta:
        description = "Detection patterns for the tool 'Stifle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Stifle"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: .NET Post-Exploitation Utility for Abusing Explicit Certificate Mappings in ADCS
        // Reference: https://github.com/logangoins/Stifle
        $string1 = /\\tStifle\.exe/ nocase ascii wide
        // Description: .NET Post-Exploitation Utility for Abusing Explicit Certificate Mappings in ADCS
        // Reference: https://github.com/logangoins/Stifle
        $string2 = "186789b7b7c4973d4f941582a796c3ced5ae7fbc4527cf19040e740d380c4106" nocase ascii wide
        // Description: .NET Post-Exploitation Utility for Abusing Explicit Certificate Mappings in ADCS
        // Reference: https://github.com/logangoins/Stifle
        $string3 = "a507307a4b6e0f6f00e8a3f3330204c124fa5a69cfc03ffd89235c7e4b77f25d" nocase ascii wide
        // Description: .NET Post-Exploitation Utility for Abusing Explicit Certificate Mappings in ADCS
        // Reference: https://github.com/logangoins/Stifle
        $string4 = "EDBAAABC-1214-41C0-8EEE-B61056DE37ED" nocase ascii wide
        // Description: .NET Post-Exploitation Utility for Abusing Explicit Certificate Mappings in ADCS
        // Reference: https://github.com/logangoins/Stifle
        $string5 = "logangoins/Stifle" nocase ascii wide
        // Description: .NET Post-Exploitation Utility for Abusing Explicit Certificate Mappings in ADCS
        // Reference: https://github.com/logangoins/Stifle
        $string6 = /Stifle\.exe\sadd\s\/object\:/ nocase ascii wide
        // Description: .NET Post-Exploitation Utility for Abusing Explicit Certificate Mappings in ADCS
        // Reference: https://github.com/logangoins/Stifle
        $string7 = /Stifle\.exe\sclear\s/ nocase ascii wide
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
