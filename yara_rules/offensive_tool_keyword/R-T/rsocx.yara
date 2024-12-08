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
        $string6 = "/rsocx/releases/download/" nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string7 = /\\rsocx\.exe/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string8 = "0908e1cfbd62968eea9ae9a3c772b6f134770c72b503affde0d551c8a55447c5" nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string9 = "79ba1aa3b1b83aeb4db3fcf649b4acffce02a559a39b10905b4eb6676a646538" nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string10 = "b23r0/rsocx" nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string11 = "cargo install rsocx" nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string12 = "cargo install rsocx" nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string13 = "f3ba88e3c7410a48b8a15edccc2ededc4468d3babf5b9c07c4166cf58606f7d2" nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string14 = "f81c31e5e8218f50da67495708f52079f59c0d96071f553086660fb47ff78e1c" nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string15 = /rsocx\s\-l\s0\.0\.0\.0/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string16 = /rsocx\s\-r\s.{0,1000}\:/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string17 = /rsocx\s\-t\s0\.0\.0\.0/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string18 = /rsocx\.exe.{0,1000}\s0\.0\.0\.0/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string19 = /rsocx\.exe.{0,1000}\s127\.0\.0\.1/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string20 = /rsocx\-main\.zip/ nocase ascii wide

    condition:
        any of them
}
