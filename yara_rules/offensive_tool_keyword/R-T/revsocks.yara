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
        $string1 = /\/kost\/revsocks\/releases/ nocase ascii wide
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
        $string10 = /\\revsocks\\.{0,1000}\.go/ nocase ascii wide
        // Description: Cross-platform SOCKS5 proxy server program/library written in C that can also reverse itself over a firewall.
        // Reference: https://github.com/emilarner/revsocks
        $string11 = /\\revsocks\\make\.bat/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string12 = /\\revsocks\-master\\/ nocase ascii wide
        // Description: Cross-platform SOCKS5 proxy server program/library written in C that can also reverse itself over a firewall.
        // Reference: https://github.com/emilarner/revsocks
        $string13 = /Cannot\ssend\sREVSOCKS_NORMAL\shandshake\!/ nocase ascii wide
        // Description: Cross-platform SOCKS5 proxy server program/library written in C that can also reverse itself over a firewall.
        // Reference: https://github.com/emilarner/revsocks
        $string14 = /emilarner\/revsocks/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string15 = /kost\/revsocks/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string16 = /revsocks\s\-\sreverse\ssocks5\sserver\/client/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string17 = /revsocks\s\-connect/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string18 = /revsocks\s\-dns/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string19 = /revsocks\s\-listen/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string20 = /revsocks_darwin_amd64/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string21 = /revsocks_freebsd_386/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string22 = /revsocks_freebsd_amd64/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string23 = /revsocks_freebsd_arm/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string24 = /revsocks_linux_386/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string25 = /revsocks_linux_amd64/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string26 = /revsocks_linux_arm/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string27 = /revsocks_linux_mips/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string28 = /revsocks_linux_mipsle/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string29 = /revsocks_linux_s390x/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string30 = /revsocks_netbsd_386/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string31 = /revsocks_netbsd_amd64/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string32 = /revsocks_netbsd_arm/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string33 = /revsocks_openbsd_386/ nocase ascii wide
        // Description: Reverse SOCKS5 implementation in Go
        // Reference: https://github.com/kost/revsocks
        $string34 = /revsocks_openbsd_amd64/ nocase ascii wide
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
        $string38 = /starting\sRevSocksServer\:\s/ nocase ascii wide

    condition:
        any of them
}
