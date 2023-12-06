rule LyncSniper
{
    meta:
        description = "Detection patterns for the tool 'LyncSniper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LyncSniper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: LyncSniper is a tool for penetration testing Lync and Skype for Business deployments hosted either on premise or in Office 365
        // Reference: https://github.com/mdsecactivebreach/LyncSniper
        $string1 = /LyncSniper/ nocase ascii wide

    condition:
        any of them
}
