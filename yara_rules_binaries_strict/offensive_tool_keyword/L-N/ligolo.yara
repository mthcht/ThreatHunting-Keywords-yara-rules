rule ligolo
{
    meta:
        description = "Detection patterns for the tool 'ligolo' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ligolo"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string1 = /\s\-relayserver\s.{0,100}\:5555/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string2 = /\/ligolo\.git/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string3 = "/ligolo-ng" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string4 = /127\.0\.0\.1\:1080/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string5 = /127\.0\.0\.1\:5555/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string6 = "bin/ligolo" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string7 = "bin/localrelay" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string8 = "cd ligolo" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string9 = "cmd/ligolo" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string10 = "cmd/ligolo" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string11 = "cmd/localrelay" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string12 = "ip link set ligolo up" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string13 = /ligolo\.lan/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string14 = "ligolo_darwin" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string15 = "ligolo_linux" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string16 = /ligolo_windows.{0,100}\.exe/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string17 = "ligolo-master" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string18 = "localrelay_linux_amd64" nocase ascii wide
        // Description: proxychains used with ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string19 = /proxychains\snmap\s\-sT\s.{0,100}\s\-p\s.{0,100}\s\-Pn\s\-A/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string20 = "proxychains rdesktop " nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string21 = "src/ligolo" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string22 = "sysdream/ligolo" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string23 = "tools/ligolo" nocase ascii wide
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
