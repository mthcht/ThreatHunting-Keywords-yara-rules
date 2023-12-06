rule GooDork
{
    meta:
        description = "Detection patterns for the tool 'GooDork' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GooDork"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: GooDork is a simple python script designed to allow you to leverage the power of google dorking straight from the comfort of your command line. GooDork offers powerfull use of googles search directives. by analyzing results from searches using regular expressions that you supply
        // Reference: https://github.com/k3170makan/GooDork
        $string1 = /GooDork/ nocase ascii wide

    condition:
        any of them
}
