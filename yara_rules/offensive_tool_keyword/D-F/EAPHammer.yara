rule EAPHammer
{
    meta:
        description = "Detection patterns for the tool 'EAPHammer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EAPHammer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: EAPHammer is a toolkit for performing targeted evil twin attacks against WPA2-Enterprise networks. It is designed to be used in full scope wireless assessments and red team engagements. As such. focus is placed on providing an easy-to-use interface that can be leveraged to execute powerful wireless attacks with minimal manual configuration. To illustrate just how fast this tool is. our Quick Start section provides an example of how to execute a credential stealing evil twin attack against a WPA/2-EAP network in just commands
        // Reference: https://github.com/s0lst1c3/eaphammer
        $string1 = /eaphammer/ nocase ascii wide

    condition:
        any of them
}
