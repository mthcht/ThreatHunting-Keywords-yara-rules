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
        $string1 = /.{0,1000}\.\/sshimpanzee.{0,1000}/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string2 = /.{0,1000}\/bin\/proxy_cli\.py.{0,1000}/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string3 = /.{0,1000}\/sshimpanzee\.git.{0,1000}/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string4 = /.{0,1000}blog\.lexfo\.fr\/sshimpanzee\.html.{0,1000}/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string5 = /.{0,1000}dns\.lexfo\.fr.{0,1000}/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string6 = /.{0,1000}git\sreset\seb88d07c43afe407094e7d609248d85a15e148ef\s\-\-hard.{0,1000}\srm\s\-f\ssshd.{0,1000}/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string7 = /.{0,1000}lexfo\/sshimpanzee.{0,1000}/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string8 = /.{0,1000}MODE\=.{0,1000}\sREMOTE\=.{0,1000}sshimpanzee.{0,1000}/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string9 = /.{0,1000}ProxyCommand\=nc\s\-lp\s8080\s\-s\s127\.0\.0\.1.{0,1000}/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string10 = /.{0,1000}sshimpanzee\s\-\-.{0,1000}/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string11 = /.{0,1000}sshimpanzee:127\.0\.0\.1:.{0,1000}/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string12 = /.{0,1000}sshimpanzee\-1\.1\-exp.{0,1000}/ nocase ascii wide
        // Description: SSHD Based implant supporting tunneling mecanisms to reach the C2 (DNS - ICMP - HTTP Encapsulation - HTTP/Socks Proxies - UDP
        // Reference: https://github.com/lexfo/sshimpanzee
        $string13 = /.{0,1000}sshimpanzee\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
