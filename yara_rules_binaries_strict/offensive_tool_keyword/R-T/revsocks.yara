rule revsocks
{
    meta:
        description = "Detection patterns for the tool 'revsocks' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "revsocks"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string1 = "/kost/revsocks/releases" nocase ascii wide
        // Description: Cross-platform SOCKS5 proxy server program/library written in C that can also reverse itself over a firewall.
        // Reference: https://github.com/emilarner/revsocks
        $string2 = /\/out\:revsocks\.exe/ nocase ascii wide
        // Description: Cross-platform SOCKS5 proxy server program/library written in C that can also reverse itself over a firewall.
        // Reference: https://github.com/emilarner/revsocks
        $string3 = /\/revsocks\.exe/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string4 = /\/revsocks\.exe/ nocase ascii wide
        // Description: Cross-platform SOCKS5 proxy server program/library written in C that can also reverse itself over a firewall.
        // Reference: https://github.com/emilarner/revsocks
        $string5 = /\/revsocks\.git/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string6 = /\/revsocks\.git/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string7 = /\\InventoryApplicationFile\\revsocks_windows/ nocase ascii wide
        // Description: Cross-platform SOCKS5 proxy server program/library written in C that can also reverse itself over a firewall.
        // Reference: https://github.com/emilarner/revsocks
        $string8 = /\\revsocks\.exe/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string9 = /\\revsocks\.exe/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string10 = /\\revsocks\\.{0,100}\.go/ nocase ascii wide
        // Description: Cross-platform SOCKS5 proxy server program/library written in C that can also reverse itself over a firewall.
        // Reference: https://github.com/emilarner/revsocks
        $string11 = /\\revsocks\\make\.bat/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string12 = /\\revsocks\-master\\/ nocase ascii wide
        // Description: Cross-platform SOCKS5 proxy server program/library written in C that can also reverse itself over a firewall.
        // Reference: https://github.com/emilarner/revsocks
        $string13 = "Cannot send REVSOCKS_NORMAL handshake!" nocase ascii wide
        // Description: Cross-platform SOCKS5 proxy server program/library written in C that can also reverse itself over a firewall.
        // Reference: https://github.com/emilarner/revsocks
        $string14 = "emilarner/revsocks" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string15 = "kost/revsocks" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string16 = "revsocks - reverse socks5 server/client" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string17 = "revsocks -connect" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string18 = "revsocks -dns" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string19 = "revsocks -listen" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string20 = "revsocks_darwin_amd64" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string21 = "revsocks_freebsd_386" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string22 = "revsocks_freebsd_amd64" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string23 = "revsocks_freebsd_arm" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string24 = "revsocks_linux_386" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string25 = "revsocks_linux_amd64" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string26 = "revsocks_linux_arm" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string27 = "revsocks_linux_mips" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string28 = "revsocks_linux_mipsle" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string29 = "revsocks_linux_s390x" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string30 = "revsocks_netbsd_386" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string31 = "revsocks_netbsd_amd64" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string32 = "revsocks_netbsd_arm" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string33 = "revsocks_openbsd_386" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string34 = "revsocks_openbsd_amd64" nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string35 = /revsocks_windows_386\.exe/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string36 = /revsocks_windows_amd64\.exe/ nocase ascii wide
        // Description: Cross-platform SOCKS5 proxy server program/library written in C that can also reverse itself over a firewall.
        // Reference: https://github.com/emilarner/revsocks
        $string37 = /revsocksserver\.h/ nocase ascii wide
        // Description: Cross-platform SOCKS5 proxy server program/library written in C that can also reverse itself over a firewall.
        // Reference: https://github.com/emilarner/revsocks
        $string38 = "starting RevSocksServer: " nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
