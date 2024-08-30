rule Get_RBCD_Threaded
{
    meta:
        description = "Detection patterns for the tool 'Get-RBCD-Threaded' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Get-RBCD-Threaded"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool to discover Resource-Based Constrained Delegation attack paths in Active Directory Environments
        // Reference: https://github.com/FatRodzianko/Get-RBCD-Threaded
        $string1 = /\.exe\s.{0,1000}\-searchforest.{0,1000}\-pwdlastset/ nocase ascii wide
        // Description: Tool to discover Resource-Based Constrained Delegation attack paths in Active Directory Environments
        // Reference: https://github.com/FatRodzianko/Get-RBCD-Threaded
        $string2 = /Get\-RBCD\-Threaded/ nocase ascii wide

    condition:
        any of them
}
