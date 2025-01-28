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
        $string3 = "/ligolo_agent"
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string4 = /\/ligolo_agent\.exe/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string5 = "/ligolo-ng" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string6 = "/ligolo-proxy" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string7 = "/ligolo-selfcert" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string8 = /\\ligolo_agent\.exe/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string9 = /\\ligolo\-proxy/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string10 = /127\.0\.0\.1\:1080/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string11 = /127\.0\.0\.1\:5555/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string12 = "bin/ligolo" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string13 = "bin/localrelay" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string14 = "cd ligolo" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string15 = "cmd/ligolo" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string16 = "cmd/localrelay" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string17 = "ip link set ligolo up"
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string18 = /ligolo\.lan/
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string19 = "ligolo_darwin"
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string20 = "ligolo_linux"
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string21 = /ligolo_windows.{0,1000}\.exe/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string22 = "ligolo-master" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string23 = "localrelay_linux_amd64"
        // Description: proxychains used with ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string24 = /proxychains\snmap\s\-sT\s.{0,1000}\s\-p\s.{0,1000}\s\-Pn\s\-A/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string25 = "proxychains rdesktop " nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string26 = "src/ligolo" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string27 = "sysdream/ligolo" nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string28 = "tools/ligolo" nocase ascii wide

    condition:
        any of them
}
