rule DNS_Hijacking
{
    meta:
        description = "Detection patterns for the tool 'DNS-Hijacking' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DNS-Hijacking"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DNS Hijacking in UNIX/Linux System by using raw socket and pcap
        // Reference: https://github.com/DyeKuu/DNS-Hijacking
        $string1 = /\/DNS\-Hijacking\.git/ nocase ascii wide
        // Description: DNS Hijacking in UNIX/Linux System by using raw socket and pcap
        // Reference: https://github.com/DyeKuu/DNS-Hijacking
        $string2 = "DyeKuu/DNS-Hijacking" nocase ascii wide

    condition:
        any of them
}
