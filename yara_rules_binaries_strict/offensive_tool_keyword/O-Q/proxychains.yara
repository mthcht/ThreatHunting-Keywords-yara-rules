rule proxychains
{
    meta:
        description = "Detection patterns for the tool 'proxychains' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "proxychains"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string1 = " proxychains " nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string2 = " -q mfsconsole" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string3 = "!!!need more proxies!!!" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string4 = /\/\.proxychains\// nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string5 = /\/etc\/proxychains\.conf/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string6 = /\/proxychains\-.{0,100}\.zip/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string7 = /\/proxychains\.conf/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string8 = /\/proxychains\.git/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string9 = "/proxychains-ng" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string10 = "36ddc7f64cb3df2ca4170627c6e0f0dea33d1a6d0730629dff6f5c633f2006f9" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string11 = "58b90ade2d52bd1436e28c1930315aa46eedd5df7ff89f4ef66554933b2792b8" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string12 = "a8c060ee140475c6ff0065e27e2274b37f7c3b9ba433ce2b406710b565ab078a" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string13 = "apt install proxychains" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string14 = "cc5f2e1b736d42c93cc10e7bab3004b24fe8c75ad565e1a65d3480b8bd1d1555" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string15 = "dea9d52d974dbe0c3598b7f75f07f6e1ef6eb835195938188942f49f9034a432" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string16 = "haad/proxychains" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string17 = "install proxychains" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string18 = "jianingy/proxychains" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string19 = "make proxychains quiet" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string20 = "proxychains -" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string21 = "proxychains cme smb" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string22 = "proxychains nmap" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string23 = "proxychains smbclient -L " nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string24 = "proxychains ssh" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string25 = "proxychains telnet" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string26 = /proxychains\.conf/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string27 = /proxychains\.lsm/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string28 = /proxychains\.sourceforge\.net/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string29 = "proxychains_proxy_count" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string30 = "proxychains4" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string31 = "proxychains-master" nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string32 = /proxychains\-other\.conf/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string33 = "proxyresolv " nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string34 = "rofl0r/proxychains" nocase ascii wide
        // Description: (TOR default) proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string35 = /socks.{0,100}127\.0\.0\.1\s9050/ nocase ascii wide
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
