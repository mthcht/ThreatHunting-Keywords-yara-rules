rule sshimpanzee
{
    meta:
        description = "Detection patterns for the tool 'sshimpanzee' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshimpanzee"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string1 = /\.\/sshimpanzee/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string2 = /\/bin\/proxy_cli\.py/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string3 = /\/sshimpanzee\.git/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string4 = /blog\.lexfo\.fr\/sshimpanzee\.html/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string5 = /dns\.lexfo\.fr/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string6 = /git\sreset\seb88d07c43afe407094e7d609248d85a15e148ef\s\-\-hard.{0,1000}\srm\s\-f\ssshd/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string7 = /lexfo\/sshimpanzee/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string8 = /MODE\=.{0,1000}\sREMOTE\=.{0,1000}sshimpanzee/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string9 = /ProxyCommand\=nc\s\-lp\s8080\s\-s\s127\.0\.0\.1/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string10 = /sshimpanzee\s\-\-/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string11 = /sshimpanzee\:127\.0\.0\.1\:/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string12 = /sshimpanzee\-1\.1\-exp/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string13 = /sshimpanzee\-main/ nocase ascii wide

    condition:
        any of them
}
