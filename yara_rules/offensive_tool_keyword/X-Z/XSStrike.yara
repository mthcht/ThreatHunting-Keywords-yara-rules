rule XSStrike
{
    meta:
        description = "Detection patterns for the tool 'XSStrike' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "XSStrike"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Advanced XSS detection and exploitation suite.
        // Reference: https://github.com/UltimateHackers/XSStrike
        $string1 = /XSStrike/ nocase ascii wide

    condition:
        any of them
}
