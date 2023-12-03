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
        $string1 = /.{0,1000}\.\/rsocx\s\-.{0,1000}/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string2 = /.{0,1000}\/rsocx\-.{0,1000}\-linux\-x86\-64\.zip.{0,1000}/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string3 = /.{0,1000}\/rsocx\-.{0,1000}\-windows\-x86\-64\.zip.{0,1000}/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string4 = /.{0,1000}\/rsocx\.exe.{0,1000}/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string5 = /.{0,1000}\/rsocx\.git.{0,1000}/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string6 = /.{0,1000}\\rsocx\.exe.{0,1000}/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string7 = /.{0,1000}b23r0\/rsocx.{0,1000}/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string8 = /.{0,1000}rsocx\s\-l\s0\.0\.0\.0.{0,1000}/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string9 = /.{0,1000}rsocx\s\-r\s.{0,1000}:.{0,1000}/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string10 = /.{0,1000}rsocx\s\-t\s0\.0\.0\.0.{0,1000}/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string11 = /.{0,1000}rsocx\.exe.{0,1000}\s0\.0\.0\.0.{0,1000}/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string12 = /.{0,1000}rsocx\.exe.{0,1000}\s127\.0\.0\.1.{0,1000}/ nocase ascii wide
        // Description: A bind/reverse Socks5 proxy server.
        // Reference: https://github.com/b23r0/rsocx
        $string13 = /.{0,1000}rsocx\-main\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
