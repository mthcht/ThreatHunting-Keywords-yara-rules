rule nbtscan
{
    meta:
        description = "Detection patterns for the tool 'nbtscan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nbtscan"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Scan for Active Machines and Gather NetBIOS Information
        // Reference: N/A
        $string1 = /nbtscan\s.{0,1000}\..{0,1000}\/24/ nocase ascii wide
        // Description: smb enumeration
        // Reference: https://github.com/charlesroelli/nbtscan
        $string2 = /nbtscan\s\-r\s.{0,1000}\/24/ nocase ascii wide
        // Description: Identify Potential Points for Man-in-the-Middle Attacks
        // Reference: N/A
        $string3 = /nbtscan\s\-s\s\:\s/ nocase ascii wide

    condition:
        any of them
}
