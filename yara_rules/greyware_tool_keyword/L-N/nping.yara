rule nping
{
    meta:
        description = "Detection patterns for the tool 'nping' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nping"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: icmp exfiltration with nping (comes with nmap)
        // Reference: http://nmap.org/nping/
        $string1 = /\s\-c1\s.{0,1000}\s\-\-data\-string\s.{0,1000}\s\-\-icmp\s/ nocase ascii wide
        // Description: icmp exfiltration with nping (comes with nmap)
        // Reference: http://nmap.org/nping/
        $string2 = /\s\-c1\s.{0,1000}\s\-\-icmp\s.{0,1000}\s\-\-data\-string\s/ nocase ascii wide
        // Description: icmp exfiltration with nping (comes with nmap)
        // Reference: http://nmap.org/nping/
        $string3 = /\s\-\-data\-string\s.{0,1000}\s\-c1\s.{0,1000}\s\-\-icmp\s/ nocase ascii wide
        // Description: icmp exfiltration with nping (comes with nmap)
        // Reference: http://nmap.org/nping/
        $string4 = /\s\-\-data\-string\s.{0,1000}\s\-\-icmp\s.{0,1000}\s\-c1\s/ nocase ascii wide
        // Description: icmp exfiltration with nping (comes with nmap)
        // Reference: http://nmap.org/nping/
        $string5 = /\s\-\-icmp\s.{0,1000}\s\-c1\s.{0,1000}\s\-\-data\-string\s/ nocase ascii wide
        // Description: icmp exfiltration with nping (comes with nmap)
        // Reference: http://nmap.org/nping/
        $string6 = /\s\-\-icmp\s.{0,1000}\s\-\-data\-string\s.{0,1000}\s\-c1\s/ nocase ascii wide
        // Description: icmp exfiltration with nping (comes with nmap)
        // Reference: http://nmap.org/nping/
        $string7 = /nping.{0,1000}\s\-\-data\s/ nocase ascii wide
        // Description: icmp exfiltration with nping (comes with nmap)
        // Reference: http://nmap.org/nping/
        $string8 = /nping.{0,1000}\s\-\-data\-string\s/ nocase ascii wide
        // Description: icmp exfiltration with nping (comes with nmap)
        // Reference: http://nmap.org/nping/
        $string9 = /nping.{0,1000}\s\-\-icmp\s/ nocase ascii wide

    condition:
        any of them
}
