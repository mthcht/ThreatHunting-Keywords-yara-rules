rule _1_6_C2
{
    meta:
        description = "Detection patterns for the tool '1.6-C2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "1.6-C2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // Reference: https://github.com/eversinc33/1.6-C2
        $string1 = /\/1\.6\-C2\.git/ nocase ascii wide
        // Description: Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // Reference: https://github.com/eversinc33/1.6-C2
        $string2 = /\\1\.6\-C2\-main\.zip/ nocase ascii wide
        // Description: Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // Reference: https://github.com/eversinc33/1.6-C2
        $string3 = /\\1_6_C2\.exe/ nocase ascii wide
        // Description: Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // Reference: https://github.com/eversinc33/1.6-C2
        $string4 = /\]\sReceived\sRCON\schallenge\:\s/ nocase ascii wide
        // Description: Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // Reference: https://github.com/eversinc33/1.6-C2
        $string5 = "01a82d6612d5698da1badc96841f2d6835e26ee95af3c536411b6d1b086da811" nocase ascii wide
        // Description: Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // Reference: https://github.com/eversinc33/1.6-C2
        $string6 = "35d3030e079a68ce10e998b5140d66fbb54b4a6e7f8ed090bf918abc42175dce" nocase ascii wide
        // Description: Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // Reference: https://github.com/eversinc33/1.6-C2
        $string7 = "c07d3356-7f9b-45e0-a4f7-7b1487d966b8" nocase ascii wide
        // Description: Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // Reference: https://github.com/eversinc33/1.6-C2
        $string8 = /eversinc33\/1\.6\-C2/ nocase ascii wide
        // Description: Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // Reference: https://github.com/eversinc33/1.6-C2
        $string9 = /getHostnameFromCVARS\(/ nocase ascii wide
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
