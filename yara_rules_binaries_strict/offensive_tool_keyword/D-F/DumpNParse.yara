rule DumpNParse
{
    meta:
        description = "Detection patterns for the tool 'DumpNParse' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpNParse"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string1 = /\/DumpNParse\.exe/ nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string2 = /\/DumpNParse\.git/ nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string3 = /\\\\windows\\\\temp\\\\lsass\.dmp/ nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string4 = /\\DumpNParse\.exe/ nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string5 = /\\DumpNParse\-main/ nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string6 = "BA1F3992-9654-4424-A0CC-26158FDFBF74" nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string7 = /C\:\\Users\\.{0,100}\\lsass_.{0,100}\.dmp/ nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string8 = /DumpNParse\-main\.zip/ nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string9 = "f038fdbc3ed50ebbf1ebc1c814836bcf93b4c149e5856ccf9b5400da8a974117" nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string10 = "icyguider/DumpNParse" nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string11 = "lsass dump saved to: " nocase ascii wide
        // Description: A Combination LSASS Dumper and LSASS Parser
        // Reference: https://github.com/icyguider/DumpNParse
        $string12 = /Program\.MiniDump\sminidump/ nocase ascii wide
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
