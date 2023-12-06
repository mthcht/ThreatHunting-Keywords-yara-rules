rule Winpayloads
{
    meta:
        description = "Detection patterns for the tool 'Winpayloads' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Winpayloads"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Undetectable Windows Payload Generation with extras Running on Python2.7
        // Reference: https://github.com/nccgroup/Winpayloads
        $string1 = /Winpayloads/ nocase ascii wide

    condition:
        any of them
}
