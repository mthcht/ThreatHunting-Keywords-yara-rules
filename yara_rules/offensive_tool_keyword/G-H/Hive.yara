rule Hive
{
    meta:
        description = "Detection patterns for the tool 'Hive' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hive"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Hive ransomware
        // Reference: https://github.com/rivitna/Malware
        $string1 = /HOW_TO_DECRYPT\.txt/ nocase ascii wide

    condition:
        any of them
}
