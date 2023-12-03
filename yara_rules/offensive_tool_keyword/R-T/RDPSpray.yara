rule RDPSpray
{
    meta:
        description = "Detection patterns for the tool 'RDPSpray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RDPSpray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool for password spraying RDP
        // Reference: https://github.com/dafthack/RDPSpray
        $string1 = /.{0,1000}RDPSpray.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
