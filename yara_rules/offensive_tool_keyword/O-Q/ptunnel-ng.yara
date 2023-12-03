rule ptunnel_ng
{
    meta:
        description = "Detection patterns for the tool 'ptunnel-ng' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ptunnel-ng"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string1 = /.{0,1000}\sptunnel\-ng.{0,1000}/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string2 = /.{0,1000}\/ptunnel\-ng.{0,1000}/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string3 = /.{0,1000}\/var\/lib\/ptunnel.{0,1000}/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string4 = /.{0,1000}nc\s127\.0\.0\.1\s4000.{0,1000}/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string5 = /.{0,1000}new\ssession\sto\s127\.0\.0\.1:3000.{0,1000}/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string6 = /.{0,1000}ptunnel\-client\.log.{0,1000}/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string7 = /.{0,1000}ptunnel\-data\-recv.{0,1000}/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string8 = /.{0,1000}ptunnel\-data\-send.{0,1000}/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string9 = /.{0,1000}ptunnel\-master.{0,1000}/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string10 = /.{0,1000}ptunnel\-ng\s.{0,1000}/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string11 = /.{0,1000}ptunnel\-ng\.conf.{0,1000}/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string12 = /.{0,1000}ptunnel\-ng\.git.{0,1000}/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string13 = /.{0,1000}ptunnel\-ng\.service.{0,1000}/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string14 = /.{0,1000}ptunnel\-ng\.te.{0,1000}/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string15 = /.{0,1000}ptunnel\-ng\-x64\.exe.{0,1000}/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string16 = /.{0,1000}ptunnel\-ng\-x64\-dbg\.exe.{0,1000}/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string17 = /.{0,1000}ptunnel\-ng\-x86\.exe.{0,1000}/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string18 = /.{0,1000}ptunnel\-ng\-x86\-dbg\.exe.{0,1000}/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string19 = /.{0,1000}ptunnel\-server\.log.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
