rule airmon_ng
{
    meta:
        description = "Detection patterns for the tool 'airmon-ng' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "airmon-ng"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This script can be used to enable monitor mode on wireless interfaces. It may also be used to kill network managers or go back from monitor mode to managed mode
        // Reference: https://www.aircrack-ng.org/doku.php?id=airmon-ng
        $string1 = /airmon\-ng/ nocase ascii wide

    condition:
        any of them
}
