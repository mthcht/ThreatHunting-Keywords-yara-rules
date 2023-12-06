rule openvas
{
    meta:
        description = "Detection patterns for the tool 'openvas' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "openvas"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Vulnerability scanner
        // Reference: https://www.openvas.org/
        $string1 = /OpenVAS/ nocase ascii wide

    condition:
        any of them
}
