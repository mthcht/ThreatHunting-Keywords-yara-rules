rule Checkmate
{
    meta:
        description = "Detection patterns for the tool 'Checkmate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Checkmate"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: payload Execution by Fake Windows SmartScreen with requires Administrator privileges & Turn off real SmartScreen Filter
        // Reference: https://github.com/S3N4T0R-0X0/Checkmate
        $string1 = /\s\-\-onefile\sCheckmate\.py/ nocase ascii wide
        // Description: payload Execution by Fake Windows SmartScreen with requires Administrator privileges & Turn off real SmartScreen Filter
        // Reference: https://github.com/S3N4T0R-0X0/Checkmate
        $string2 = "9be92d43d374ae72fbc28b078e1083e674ebe4da30f4f815aa9d86150b4fe024" nocase ascii wide
        // Description: payload Execution by Fake Windows SmartScreen with requires Administrator privileges & Turn off real SmartScreen Filter
        // Reference: https://github.com/S3N4T0R-0X0/Checkmate
        $string3 = /C\:\\Users\\username\\command_log\.txt/ nocase ascii wide
        // Description: payload Execution by Fake Windows SmartScreen with requires Administrator privileges & Turn off real SmartScreen Filter
        // Reference: https://github.com/S3N4T0R-0X0/Checkmate
        $string4 = /C\:\\Users\\username\\payload\.exe/ nocase ascii wide
        // Description: payload Execution by Fake Windows SmartScreen with requires Administrator privileges & Turn off real SmartScreen Filter
        // Reference: https://github.com/S3N4T0R-0X0/Checkmate
        $string5 = "e50c620c59b9a402d924b65695c6ee723cf10bbf65c542416888776f3b58282f" nocase ascii wide
        // Description: payload Execution by Fake Windows SmartScreen with requires Administrator privileges & Turn off real SmartScreen Filter
        // Reference: https://github.com/S3N4T0R-0X0/Checkmate
        $string6 = /os\.system\(\'reg\sadd\s\\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet\sSettings\\"\s\/v\s\\"EnableSmartScreenFilter\\"\s\/t\sREG_DWORD\s\/d\s\\"0\\"\s\/f\'\)/ nocase ascii wide
        // Description: payload Execution by Fake Windows SmartScreen with requires Administrator privileges & Turn off real SmartScreen Filter
        // Reference: https://github.com/S3N4T0R-0X0/Checkmate
        $string7 = "S3N4T0R-0X0/Checkmate" nocase ascii wide
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
