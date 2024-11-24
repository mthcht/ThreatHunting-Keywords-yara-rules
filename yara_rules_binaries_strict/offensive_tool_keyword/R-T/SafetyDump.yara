rule SafetyDump
{
    meta:
        description = "Detection patterns for the tool 'SafetyDump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SafetyDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string1 = /\/SafetyDump\.exe/ nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string2 = /\/SafetyDump\.git/ nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string3 = /\\SafetyDump\.csproj/ nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string4 = /\\SafetyDump\.exe/ nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string5 = /\\SafetyDump\.sln/ nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string6 = "738f3dce5ad63a16b2cf8b236d8d374022f121c0990e92adc214a6d03b0dc345" nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string7 = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string8 = "88888dcb2ac77d09b3c68c26f025f1e1ba9db667f3950a79a110896de297e162" nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string9 = "989cb6a23ecba5fb7785a1e23b61b84c12ff45723eb98bb885905768e0a9550a" nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string10 = "namespace SafetyDump" nocase ascii wide
        // Description: in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string11 = "riskydissonance/SafetyDump" nocase ascii wide
        // Description: uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output. This allows the dump to be redirected to a file or straight back down C2 or through other tools
        // Reference: https://github.com/riskydissonance/SafetyDump
        $string12 = /SafetyDump\.exe\s/ nocase ascii wide
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
