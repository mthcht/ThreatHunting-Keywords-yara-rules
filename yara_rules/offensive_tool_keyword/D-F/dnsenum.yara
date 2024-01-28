rule dnsenum
{
    meta:
        description = "Detection patterns for the tool 'dnsenum' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnsenum"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks.
        // Reference: https://github.com/fwaeytens/dnsenum
        $string1 = /dnsenum\.pl/ nocase ascii wide

    condition:
        any of them
}
