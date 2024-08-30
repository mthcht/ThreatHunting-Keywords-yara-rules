rule nping
{
    meta:
        description = "Detection patterns for the tool 'nping' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nping"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Nping is an open source tool for network packet generation. response analysis and response time measurement. Nping can generate network packets for a wide range of protocols. allowing users full control over protocol headers. While Nping can be used as a simple ping utility to detect active hosts. it can also be used as a raw packet generator for network stack stress testing. ARP poisoning. Denial of Service attacks. route tracing. etc. Npings novel echo mode lets users see how packets change in transit between the source and destination hosts. Thats a great way to understand firewall rules. detect packet corruption. and more
        // Reference: https://nmap.org/nping/
        $string1 = /nping\s\-/ nocase ascii wide

    condition:
        any of them
}
