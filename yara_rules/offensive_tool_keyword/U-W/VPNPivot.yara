rule VPNPivot
{
    meta:
        description = "Detection patterns for the tool 'VPNPivot' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VPNPivot"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Sometime we do external penetration testing and when we compromise the remote target we would like to explore the internal network behind and getting such compromise like owning Active directory. accessing shared files. conducting MITM attacks ... etc
        // Reference: https://github.com/0x36/VPNPivot
        $string1 = /VPNPivot/ nocase ascii wide

    condition:
        any of them
}
