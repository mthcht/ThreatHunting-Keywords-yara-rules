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
        $string1 = /\sptunnel\-ng/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string2 = /\/ptunnel\-ng/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string3 = /\/var\/lib\/ptunnel/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string4 = /nc\s127\.0\.0\.1\s4000/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string5 = /new\ssession\sto\s127\.0\.0\.1\:3000/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string6 = /ptunnel\-client\.log/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string7 = /ptunnel\-data\-recv/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string8 = /ptunnel\-data\-send/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string9 = /ptunnel\-master/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string10 = /ptunnel\-ng\s/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string11 = /ptunnel\-ng\.conf/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string12 = /ptunnel\-ng\.git/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string13 = /ptunnel\-ng\.service/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string14 = /ptunnel\-ng\.te/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string15 = /ptunnel\-ng\-x64\.exe/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string16 = /ptunnel\-ng\-x64\-dbg\.exe/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string17 = /ptunnel\-ng\-x86\.exe/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string18 = /ptunnel\-ng\-x86\-dbg\.exe/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string19 = /ptunnel\-server\.log/ nocase ascii wide

    condition:
        any of them
}
