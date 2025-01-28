rule nsocks
{
    meta:
        description = "Detection patterns for the tool 'nsocks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nsocks"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: .NET HttpClient proxy handler implementation for SOCKS proxies
        // Reference: https://github.com/bbepis/Nsocks
        $string1 = /\/nsocks\.dll/ nocase ascii wide
        // Description: .NET HttpClient proxy handler implementation for SOCKS proxies
        // Reference: https://github.com/bbepis/Nsocks
        $string2 = /\/NSocks\.git/ nocase ascii wide
        // Description: .NET HttpClient proxy handler implementation for SOCKS proxies
        // Reference: https://github.com/bbepis/Nsocks
        $string3 = /\\nsocks\.dll/ nocase ascii wide
        // Description: .NET HttpClient proxy handler implementation for SOCKS proxies
        // Reference: https://github.com/bbepis/Nsocks
        $string4 = /\\nsocks\.exe/ nocase ascii wide
        // Description: .NET HttpClient proxy handler implementation for SOCKS proxies
        // Reference: https://github.com/bbepis/Nsocks
        $string5 = /\>Nsocks\.dll\</ nocase ascii wide
        // Description: .NET HttpClient proxy handler implementation for SOCKS proxies
        // Reference: https://github.com/bbepis/Nsocks
        $string6 = ">Nsocks<" nocase ascii wide
        // Description: .NET HttpClient proxy handler implementation for SOCKS proxies
        // Reference: https://github.com/bbepis/Nsocks
        $string7 = "2e777ea84aa3cca0a17f3a08776d0bb993ad0ca42b2276429f13e7e036d51746" nocase ascii wide
        // Description: .NET HttpClient proxy handler implementation for SOCKS proxies
        // Reference: https://github.com/bbepis/Nsocks
        $string8 = "889E3D8B-58FA-462D-A2D8-3CB430484B6A" nocase ascii wide
        // Description: .NET HttpClient proxy handler implementation for SOCKS proxies
        // Reference: https://github.com/bbepis/Nsocks
        $string9 = "bbepis/Nsocks" nocase ascii wide
        // Description: .NET HttpClient proxy handler implementation for SOCKS proxies
        // Reference: https://github.com/bbepis/Nsocks
        $string10 = "CE5C7EF9-E890-48E5-8551-3E8F96DCB38F" nocase ascii wide
        // Description: .NET HttpClient proxy handler implementation for SOCKS proxies
        // Reference: https://github.com/bbepis/Nsocks
        $string11 = "f283690950663e8831078bd3f7d02835047997f65445f90a364626fb835809c4" nocase ascii wide
        // Description: socks5 proxy provider
        // Reference: https://nsocks.net
        $string12 = /https\:\/\/nsocks\.net\/proxy/ nocase ascii wide
        // Description: socks5 proxy provider
        // Reference: https://nsocks.net
        $string13 = /https\:\/\/nsocks4pvtcewb2ora3zk47ksx7dvazbxyhzp4myhegpthgkphpi7aad\.onion\// nocase ascii wide
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
