rule sniffglue
{
    meta:
        description = "Detection patterns for the tool 'sniffglue' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sniffglue"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Secure multithreaded packet sniffer
        // Reference: https://github.com/kpcyrd/sniffglue
        $string1 = /sniffglue/ nocase ascii wide

    condition:
        any of them
}
