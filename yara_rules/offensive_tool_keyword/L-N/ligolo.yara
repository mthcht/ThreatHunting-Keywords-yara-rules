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
        $string1 = /\s\-relayserver\s.{0,1000}\:5555/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string2 = /\/ligolo\.git/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string3 = /\/ligolo\-ng/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string4 = /127\.0\.0\.1\:1080/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string5 = /127\.0\.0\.1\:5555/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string6 = /bin\/ligolo/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string7 = /bin\/localrelay/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string8 = /cd\sligolo/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string9 = /cmd\/ligolo/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string10 = /cmd\/ligolo/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string11 = /cmd\/localrelay/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string12 = /ip\slink\sset\sligolo\sup/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string13 = /ligolo\.lan/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string14 = /ligolo_darwin/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string15 = /ligolo_linux/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string16 = /ligolo_windows.{0,1000}\.exe/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string17 = /ligolo\-master/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string18 = /localrelay_linux_amd64/ nocase ascii wide
        // Description: proxychains used with ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string19 = /proxychains\snmap\s\-sT\s.{0,1000}\s\-p\s.{0,1000}\s\-Pn\s\-A/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string20 = /proxychains\srdesktop\s/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string21 = /src\/ligolo/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string22 = /sysdream\/ligolo/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string23 = /tools\/ligolo/ nocase ascii wide

    condition:
        any of them
}
