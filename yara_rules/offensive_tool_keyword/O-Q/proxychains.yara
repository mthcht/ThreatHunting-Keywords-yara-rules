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
        $string1 = /.{0,1000}\sproxychains\s.{0,1000}/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string2 = /.{0,1000}\/proxychains\.git.{0,1000}/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string3 = /.{0,1000}haad\/proxychains.{0,1000}/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string4 = /.{0,1000}install\sproxychains.{0,1000}/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string5 = /.{0,1000}proxychains\s\-.{0,1000}/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string6 = /.{0,1000}proxychains\snmap.{0,1000}/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string7 = /.{0,1000}proxychains\ssmbclient\s\-L\s.{0,1000}/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string8 = /.{0,1000}proxychains\stelnet.{0,1000}/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string9 = /.{0,1000}proxychains\.conf.{0,1000}/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string10 = /.{0,1000}proxychains\.lsm.{0,1000}/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string11 = /.{0,1000}proxychains\.sourceforge\.net.{0,1000}/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string12 = /.{0,1000}proxychains\-master.{0,1000}/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string13 = /.{0,1000}proxychains\-other\.conf.{0,1000}/ nocase ascii wide
        // Description: (TOR default) proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string14 = /.{0,1000}socks.{0,1000}127\.0\.0\.1\s9050.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
