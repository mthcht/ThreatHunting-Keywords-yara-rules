rule sniffer
{
    meta:
        description = "Detection patterns for the tool 'sniffer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sniffer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A modern alternative network traffic sniffer.
        // Reference: https://github.com/chenjiandongx/sniffer
        $string1 = /\/sniffer\.git/ nocase ascii wide
        // Description: A modern alternative network traffic sniffer.
        // Reference: https://github.com/chenjiandongx/sniffer
        $string2 = "brew install sniffer" nocase ascii wide
        // Description: A modern alternative network traffic sniffer.
        // Reference: https://github.com/chenjiandongx/sniffer
        $string3 = "chenjiandongx/sniffer" nocase ascii wide
        // Description: A modern alternative network traffic sniffer.
        // Reference: https://github.com/chenjiandongx/sniffer
        $string4 = /sniffer\-master\.zip/ nocase ascii wide

    condition:
        any of them
}
