rule LinikatzV2
{
    meta:
        description = "Detection patterns for the tool 'LinikatzV2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LinikatzV2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/Orange-Cyberdefense/LinikatzV2
        $string1 = /.{0,1000}\/LinikatzV2\/.{0,1000}/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/Orange-Cyberdefense/LinikatzV2
        $string2 = /.{0,1000}\\LinikatzV2\\.{0,1000}/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/Orange-Cyberdefense/LinikatzV2
        $string3 = /.{0,1000}kerberos_steal.{0,1000}/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/Orange-Cyberdefense/LinikatzV2
        $string4 = /.{0,1000}linikatzV2\.sh.{0,1000}/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/Orange-Cyberdefense/LinikatzV2
        $string5 = /.{0,1000}Orange\-Cyberdefense\/LinikatzV2.{0,1000}/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/Orange-Cyberdefense/LinikatzV2
        $string6 = /.{0,1000}SSSDKCMExtractor\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
