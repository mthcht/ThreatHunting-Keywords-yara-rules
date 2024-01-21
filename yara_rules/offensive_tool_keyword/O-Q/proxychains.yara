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
        $string1 = /\sproxychains\s/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string2 = /\/proxychains\.git/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string3 = /haad\/proxychains/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string4 = /install\sproxychains/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string5 = /proxychains\s\-/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string6 = /proxychains\scme\ssmb/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string7 = /proxychains\snmap/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string8 = /proxychains\ssmbclient\s\-L\s/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string9 = /proxychains\stelnet/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string10 = /proxychains\.conf/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string11 = /proxychains\.lsm/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string12 = /proxychains\.sourceforge\.net/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string13 = /proxychains\-master/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string14 = /proxychains\-other\.conf/ nocase ascii wide
        // Description: (TOR default) proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string15 = /socks.{0,1000}127\.0\.0\.1\s9050/ nocase ascii wide

    condition:
        any of them
}
