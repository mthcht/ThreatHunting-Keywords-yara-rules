rule arp
{
    meta:
        description = "Detection patterns for the tool 'arp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "arp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Arp displays and modifies information about a system's Address Resolution Protocol (ARP) cache
        // Reference: N/A
        $string1 = /\\"C\:\\Windows\\system32\\ARP\.EXE\\"\s\/a/ nocase ascii wide

    condition:
        any of them
}
