rule rapid7
{
    meta:
        description = "Detection patterns for the tool 'rapid7' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rapid7"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Vulnerability scanner
        // Reference: https://www.rapid7.com/
        $string1 = /Rapid7/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://www.rapid7.com/
        $string2 = /test\.endpoint\.rapid7\.com/ nocase ascii wide

    condition:
        any of them
}
