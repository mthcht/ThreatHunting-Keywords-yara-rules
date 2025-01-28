rule AtlasC2
{
    meta:
        description = "Detection patterns for the tool 'AtlasC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AtlasC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string1 = /AtlasC2.{0,100}APIModels/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string2 = /AtlasC2.{0,100}Client/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string3 = /AtlasC2.{0,100}implant/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string4 = /AtlasC2.{0,100}TeamServer/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string5 = /AtlasC2\.exe/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string6 = /AtlasC2b\.exe/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string7 = /AtlasC2b\.sln/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string8 = /AtlasImplant\.yar/ nocase ascii wide
        // Description: C# C2 Framework centered around Stage 1 operations
        // Reference: https://github.com/Gr1mmie/AtlasC2
        $string9 = "Gr1mmie/AtlasC2" nocase ascii wide
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
