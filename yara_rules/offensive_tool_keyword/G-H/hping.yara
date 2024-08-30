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
        $string1 = /\shping3\s/ nocase ascii wide
        // Description: hping3 is a network tool able to send custom TCP/IP
        // Reference: https://github.com/antirez/hping
        $string2 = /\.\/hping\s/ nocase ascii wide
        // Description: hping3 is a network tool able to send custom TCP/IP
        // Reference: https://github.com/antirez/hping
        $string3 = /antirez\/hping/ nocase ascii wide
        // Description: hping3 is a network tool able to send custom TCP/IP packets and to display target replies like ping do with ICMP replies. hping3 can handle fragmentation
        // Reference: https://github.com/antirez/hping
        $string4 = /hping2\.h/ nocase ascii wide
        // Description: hping3 is a network tool able to send custom TCP/IP
        // Reference: https://github.com/antirez/hping
        $string5 = /hping3\s\-/ nocase ascii wide
        // Description: hping3 is a network tool able to send custom TCP/IP
        // Reference: https://github.com/antirez/hping
        $string6 = /install\shping3/ nocase ascii wide

    condition:
        any of them
}
