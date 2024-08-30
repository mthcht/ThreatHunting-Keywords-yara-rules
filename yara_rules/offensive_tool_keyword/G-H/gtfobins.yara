rule gtfobins
{
    meta:
        description = "Detection patterns for the tool 'gtfobins' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gtfobins"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: GTFOBins is a curated list of Unix binaries that can used to bypass local security restrictions in misconfigured systems malicious use of legitimate binaries
        // Reference: https://gtfobins.github.io/
        $string1 = /gtfobins/ nocase ascii wide

    condition:
        any of them
}
