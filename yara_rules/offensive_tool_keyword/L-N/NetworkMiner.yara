rule NetworkMiner
{
    meta:
        description = "Detection patterns for the tool 'NetworkMiner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetworkMiner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Network Forensic Analysis Tool (NFAT)
        // Reference: http://www.netresec.com/?page=NetworkMiner
        $string1 = /NetworkMiner/ nocase ascii wide

    condition:
        any of them
}
