rule rsocx
{
    meta:
        description = "Detection patterns for the tool 'rsocx' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rsocx"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string1 = /\.\/rsocx\s\-/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string2 = /\/rsocx\-.{0,1000}\-linux\-x86\-64\.zip/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string3 = /\/rsocx\-.{0,1000}\-windows\-x86\-64\.zip/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string4 = /\/rsocx\.exe/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string5 = /\/rsocx\.git/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string6 = /\\rsocx\.exe/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string7 = /b23r0\/rsocx/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string8 = /rsocx\s\-l\s0\.0\.0\.0/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string9 = /rsocx\s\-r\s.{0,1000}\:/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string10 = /rsocx\s\-t\s0\.0\.0\.0/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string11 = /rsocx\.exe.{0,1000}\s0\.0\.0\.0/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string12 = /rsocx\.exe.{0,1000}\s127\.0\.0\.1/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string13 = /rsocx\-main\.zip/ nocase ascii wide

    condition:
        any of them
}
