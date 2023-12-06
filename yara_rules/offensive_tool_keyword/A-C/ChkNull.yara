rule ChkNull
{
    meta:
        description = "Detection patterns for the tool 'ChkNull' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ChkNull"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Checks for Users with No passwords
        // Reference: https://github.com/nyxgeek/classic_hacking_tools
        $string1 = /chknull\.zip/ nocase ascii wide

    condition:
        any of them
}
