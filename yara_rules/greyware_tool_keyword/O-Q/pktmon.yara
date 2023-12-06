rule pktmon
{
    meta:
        description = "Detection patterns for the tool 'pktmon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pktmon"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: pktmon network diagnostics tool for Windows that can be used for packet capture - packet drop detection - packet filtering and counting.
        // Reference: https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon
        $string1 = /pktmon\sstart/ nocase ascii wide

    condition:
        any of them
}
