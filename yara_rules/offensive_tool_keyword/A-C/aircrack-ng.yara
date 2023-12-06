rule aircrack_ng
{
    meta:
        description = "Detection patterns for the tool 'aircrack-ng' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "aircrack-ng"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WiFi security auditing tools suite.
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string1 = /Aircrack\-ng/ nocase ascii wide

    condition:
        any of them
}
