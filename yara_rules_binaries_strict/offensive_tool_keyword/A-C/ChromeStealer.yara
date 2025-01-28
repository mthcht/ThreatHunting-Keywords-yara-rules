rule ChromeStealer
{
    meta:
        description = "Detection patterns for the tool 'ChromeStealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ChromeStealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: extract and decrypt stored passwords from Google Chrome
        // Reference: https://github.com/BernKing/ChromeStealer
        $string1 = /\/ChromeStealer\.git/ nocase ascii wide
        // Description: extract and decrypt stored passwords from Google Chrome
        // Reference: https://github.com/BernKing/ChromeStealer
        $string2 = /\\ChromeStealer\.cpp/ nocase ascii wide
        // Description: extract and decrypt stored passwords from Google Chrome
        // Reference: https://github.com/BernKing/ChromeStealer
        $string3 = /\\ChromeStealer\.sln/ nocase ascii wide
        // Description: extract and decrypt stored passwords from Google Chrome
        // Reference: https://github.com/BernKing/ChromeStealer
        $string4 = /\\ChromeStealer\-main/ nocase ascii wide
        // Description: extract and decrypt stored passwords from Google Chrome
        // Reference: https://github.com/BernKing/ChromeStealer
        $string5 = "1aebc75f4a66ba1711c288235dad6ac01c59e8801e8a1c2151cbb7dfd4c2c098" nocase ascii wide
        // Description: extract and decrypt stored passwords from Google Chrome
        // Reference: https://github.com/BernKing/ChromeStealer
        $string6 = "64d2173109cdc67df6e9e15a275b4ed0b5488397c290b996ffd3ed445f361b79" nocase ascii wide
        // Description: extract and decrypt stored passwords from Google Chrome
        // Reference: https://github.com/BernKing/ChromeStealer
        $string7 = "BernKing/ChromeStealer" nocase ascii wide
        // Description: extract and decrypt stored passwords from Google Chrome
        // Reference: https://github.com/BernKing/ChromeStealer
        $string8 = "c7c8b6fb-4e59-494e-aeeb-40cf342a7e88" nocase ascii wide
        // Description: extract and decrypt stored passwords from Google Chrome
        // Reference: https://github.com/BernKing/ChromeStealer
        $string9 = /ChromeStealer\.exe/ nocase ascii wide
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
