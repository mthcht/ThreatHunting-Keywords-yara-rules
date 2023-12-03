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
        $string1 = /.{0,1000}\s\-relayserver\s.{0,1000}:5555.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string2 = /.{0,1000}\/ligolo\.git.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string3 = /.{0,1000}\/ligolo\-ng.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string4 = /.{0,1000}127\.0\.0\.1:1080.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string5 = /.{0,1000}127\.0\.0\.1:5555.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string6 = /.{0,1000}bin\/ligolo.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string7 = /.{0,1000}bin\/localrelay.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string8 = /.{0,1000}cd\sligolo.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string9 = /.{0,1000}cmd\/ligolo.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string10 = /.{0,1000}cmd\/ligolo.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string11 = /.{0,1000}cmd\/localrelay.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string12 = /.{0,1000}ip\slink\sset\sligolo\sup.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string13 = /.{0,1000}ligolo\.lan.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string14 = /.{0,1000}ligolo_darwin.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string15 = /.{0,1000}ligolo_linux.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string16 = /.{0,1000}ligolo_windows.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string17 = /.{0,1000}ligolo\-master.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string18 = /.{0,1000}localrelay_linux_amd64.{0,1000}/ nocase ascii wide
        // Description: proxychains used with ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string19 = /.{0,1000}proxychains\snmap\s\-sT\s.{0,1000}\s\-p\s.{0,1000}\s\-Pn\s\-A.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string20 = /.{0,1000}proxychains\srdesktop\s.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string21 = /.{0,1000}src\/ligolo.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string22 = /.{0,1000}sysdream\/ligolo.{0,1000}/ nocase ascii wide
        // Description: ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve)
        // Reference: https://github.com/sysdream/ligolo
        $string23 = /.{0,1000}tools\/ligolo.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
