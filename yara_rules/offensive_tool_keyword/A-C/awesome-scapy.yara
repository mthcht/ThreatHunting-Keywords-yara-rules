rule awesome_scapy
{
    meta:
        description = "Detection patterns for the tool 'awesome-scapy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "awesome-scapy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Python tool and library for low level packet creation and manipulation
        // Reference: https://github.com/secdev/awesome-scapy
        $string1 = /awesome\-scapy/ nocase ascii wide

    condition:
        any of them
}
