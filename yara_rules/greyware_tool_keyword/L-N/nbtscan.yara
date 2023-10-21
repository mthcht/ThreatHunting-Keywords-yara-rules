rule nbtscan
{
    meta:
        description = "Detection patterns for the tool 'nbtscan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nbtscan"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: smb enumeration
        // Reference: https://github.com/charlesroelli/nbtscan
        $string1 = /nbtscan\s\-r\s.*\/24/ nocase ascii wide

    condition:
        any of them
}