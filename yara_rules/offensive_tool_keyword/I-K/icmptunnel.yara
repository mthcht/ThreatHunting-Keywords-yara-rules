rule icmptunnel
{
    meta:
        description = "Detection patterns for the tool 'icmptunnel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "icmptunnel"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: icmptunnel works by encapsulating your IP traffic in ICMP echo packets and sending them to your own proxy server. The proxy server decapsulates the packet and forwards the IP traffic. The incoming IP packets which are destined for the client are again encapsulated in ICMP reply packets and sent back to the client. The IP traffic is sent in the 'data' field of ICMP packets.
        // Reference: https://github.com/s-h-3-l-l/katoolin3
        $string1 = /icmptunnel/ nocase ascii wide

    condition:
        any of them
}
