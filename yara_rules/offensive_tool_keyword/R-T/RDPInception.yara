rule RDPInception
{
    meta:
        description = "Detection patterns for the tool 'RDPInception' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RDPInception"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A proof of concept for the RDP Inception Attack
        // Reference: https://github.com/mdsecactivebreach/RDPInception
        $string1 = /RDPInception/ nocase ascii wide

    condition:
        any of them
}
