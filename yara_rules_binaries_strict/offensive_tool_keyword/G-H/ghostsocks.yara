rule ghostsocks
{
    meta:
        description = "Detection patterns for the tool 'ghostsocks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ghostsocks"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string1 = /\.ghostsocks\.json/ nocase ascii wide
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string2 = /\/ghostsocks\.git/ nocase ascii wide
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string3 = /\\ghostsocks\-master/ nocase ascii wide
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string4 = "28625926a22131062b34670f36dafb312c2631b576bcfa0f9544994de77b6544" nocase ascii wide
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string5 = "ca94d5a554af633b96f7a6b0e4b8891b4a1e30812df356f7bc21e99dbce90d8e" nocase ascii wide
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string6 = "DefaultListenAddr = \":7448\"" nocase ascii wide
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string7 = "ghostsocks-local" nocase ascii wide
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string8 = "ghostsocks-server" nocase ascii wide
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string9 = "LemonSaaS/ghostsocks" nocase ascii wide
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
