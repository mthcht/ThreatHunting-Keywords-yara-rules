rule hping
{
    meta:
        description = "Detection patterns for the tool 'hping' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hping"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: hping3 is a network tool able to send custom TCP/IP
        // Reference: https://github.com/antirez/hping
        $string1 = /.{0,1000}\shping3\s.{0,1000}/ nocase ascii wide
        // Description: hping3 is a network tool able to send custom TCP/IP
        // Reference: https://github.com/antirez/hping
        $string2 = /.{0,1000}\.\/hping\s.{0,1000}/ nocase ascii wide
        // Description: hping3 is a network tool able to send custom TCP/IP
        // Reference: https://github.com/antirez/hping
        $string3 = /.{0,1000}antirez\/hping.{0,1000}/ nocase ascii wide
        // Description: hping3 is a network tool able to send custom TCP/IP packets and to display target replies like ping do with ICMP replies. hping3 can handle fragmentation
        // Reference: https://github.com/antirez/hping
        $string4 = /.{0,1000}hping2\.h.{0,1000}/ nocase ascii wide
        // Description: hping3 is a network tool able to send custom TCP/IP
        // Reference: https://github.com/antirez/hping
        $string5 = /.{0,1000}hping3\s\-.{0,1000}/ nocase ascii wide
        // Description: hping3 is a network tool able to send custom TCP/IP
        // Reference: https://github.com/antirez/hping
        $string6 = /.{0,1000}install\shping3.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
