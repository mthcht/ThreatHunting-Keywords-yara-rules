rule qu_ax
{
    meta:
        description = "Detection patterns for the tool 'qu.ax' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "qu.ax"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: qu.ax is a quick and private file hosting service - abused by threat actors
        // Reference: https://qu[.]ax/
        $string1 = /https\:\/\/qu\.ax\/.{0,1000}\./ nocase ascii wide

    condition:
        any of them
}
