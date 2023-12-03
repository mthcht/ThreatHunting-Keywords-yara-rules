rule aquatone
{
    meta:
        description = "Detection patterns for the tool 'aquatone' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "aquatone"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Aquatone is a tool for visual inspection of websites across a large amount of hosts and is convenient for quickly gaining an overview of HTTP-based attack surface.
        // Reference: https://github.com/michenriksen/aquatone
        $string1 = /.{0,1000}aquatone.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
