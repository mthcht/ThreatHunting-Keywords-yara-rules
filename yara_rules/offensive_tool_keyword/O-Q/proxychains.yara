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
        $string2 = /\s\-q\smfsconsole/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string3 = /\!\!\!need\smore\sproxies\!\!\!/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string4 = /\/\.proxychains\// nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string5 = /\/etc\/proxychains\.conf/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string6 = /\/proxychains\-.{0,1000}\.zip/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string7 = /\/proxychains\.conf/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string8 = /\/proxychains\.git/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string9 = /\/proxychains\-ng/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string10 = /36ddc7f64cb3df2ca4170627c6e0f0dea33d1a6d0730629dff6f5c633f2006f9/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string11 = /58b90ade2d52bd1436e28c1930315aa46eedd5df7ff89f4ef66554933b2792b8/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string12 = /a8c060ee140475c6ff0065e27e2274b37f7c3b9ba433ce2b406710b565ab078a/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string13 = /apt\sinstall\sproxychains/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string14 = /cc5f2e1b736d42c93cc10e7bab3004b24fe8c75ad565e1a65d3480b8bd1d1555/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string15 = /dea9d52d974dbe0c3598b7f75f07f6e1ef6eb835195938188942f49f9034a432/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string16 = /haad\/proxychains/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string17 = /install\sproxychains/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string18 = /jianingy\/proxychains/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string19 = /make\sproxychains\squiet/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string20 = /proxychains\s\-/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string21 = /proxychains\scme\ssmb/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string22 = /proxychains\snmap/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string23 = /proxychains\ssmbclient\s\-L\s/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string24 = /proxychains\stelnet/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string25 = /proxychains\.conf/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string26 = /proxychains\.lsm/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string27 = /proxychains\.sourceforge\.net/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string28 = /proxychains_proxy_count/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string29 = /proxychains4/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string30 = /proxychains\-master/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string31 = /proxychains\-other\.conf/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string32 = /proxyresolv\s/ nocase ascii wide
        // Description: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string33 = /rofl0r\/proxychains/ nocase ascii wide
        // Description: (TOR default) proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4 SOCKS5 or HTTP(S) proxy
        // Reference: https://github.com/haad/proxychains
        $string34 = /socks.{0,1000}127\.0\.0\.1\s9050/ nocase ascii wide

    condition:
        any of them
}
