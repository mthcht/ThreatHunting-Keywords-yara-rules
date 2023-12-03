rule LAPSDecrypt
{
    meta:
        description = "Detection patterns for the tool 'LAPSDecrypt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LAPSDecrypt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Quick POC looking at how encryption works for LAPS (v2)
        // Reference: https://gist.github.com/xpn/23dc5b6c260a7571763ca8ca745c32f4
        $string1 = /.{0,1000}LAPSDecrypt\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
