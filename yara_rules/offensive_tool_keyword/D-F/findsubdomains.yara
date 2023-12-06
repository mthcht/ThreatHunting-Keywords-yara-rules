rule findsubdomains
{
    meta:
        description = "Detection patterns for the tool 'findsubdomains' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "findsubdomains"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A subdomains discovery tool that collects all possible subdomains from open source internet and validates them through various tools to provide accurate results.
        // Reference: https://findsubdomains.com/
        $string1 = /Findsubdomains/ nocase ascii wide

    condition:
        any of them
}
