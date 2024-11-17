rule TimeException
{
    meta:
        description = "Detection patterns for the tool 'TimeException' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TimeException"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to find folders excluded from AV real-time scanning using a time oracle
        // Reference: https://github.com/bananabr/TimeException
        $string1 = /\.exe\s\-\-sample\-size\s1000\s\-\-mode\s0\s\-\-targets\sdirs\.txt/ nocase ascii wide
        // Description: A tool to find folders excluded from AV real-time scanning using a time oracle
        // Reference: https://github.com/bananabr/TimeException
        $string2 = /\.exe\s\-\-sample\-size\s1000\s\-\-mode\s1\s\-\-targets\sexts\.txt/ nocase ascii wide
        // Description: A tool to find folders excluded from AV real-time scanning using a time oracle
        // Reference: https://github.com/bananabr/TimeException
        $string3 = /\/TimeException\.exe/ nocase ascii wide
        // Description: A tool to find folders excluded from AV real-time scanning using a time oracle
        // Reference: https://github.com/bananabr/TimeException
        $string4 = /\/TimeException\.git/ nocase ascii wide
        // Description: A tool to find folders excluded from AV real-time scanning using a time oracle
        // Reference: https://github.com/bananabr/TimeException
        $string5 = /\\TimeException\.cpp/ nocase ascii wide
        // Description: A tool to find folders excluded from AV real-time scanning using a time oracle
        // Reference: https://github.com/bananabr/TimeException
        $string6 = /\\TimeException\.exe/ nocase ascii wide
        // Description: A tool to find folders excluded from AV real-time scanning using a time oracle
        // Reference: https://github.com/bananabr/TimeException
        $string7 = /\\TimeException\-main/ nocase ascii wide
        // Description: A tool to find folders excluded from AV real-time scanning using a time oracle
        // Reference: https://github.com/bananabr/TimeException
        $string8 = /30fb8b27a7636a8922aff3018b2b612bf224a17bf7a9c9f2f2a01d4f7754c522/ nocase ascii wide
        // Description: A tool to find folders excluded from AV real-time scanning using a time oracle
        // Reference: https://github.com/bananabr/TimeException
        $string9 = /bananabr\/TimeException/ nocase ascii wide
        // Description: A tool to find folders excluded from AV real-time scanning using a time oracle
        // Reference: https://github.com/bananabr/TimeException
        $string10 = /c6a8d755e4764335fa9c5313c6ba641ac9a0228648065667f7d535457dbf0ceb/ nocase ascii wide
        // Description: A tool to find folders excluded from AV real-time scanning using a time oracle
        // Reference: https://github.com/bananabr/TimeException
        $string11 = /e69f0324\-3afb\-485e\-92c7\-cb097ea47caf/ nocase ascii wide
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
