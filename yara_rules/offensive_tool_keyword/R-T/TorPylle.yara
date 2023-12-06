rule TorPylle
{
    meta:
        description = "Detection patterns for the tool 'TorPylle' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TorPylle"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Python / Scapy implementation of the OR (TOR) protocol.
        // Reference: https://github.com/cea-sec/TorPylle
        $string1 = /TorPylle/ nocase ascii wide

    condition:
        any of them
}
