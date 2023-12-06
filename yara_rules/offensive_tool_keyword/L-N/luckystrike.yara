rule luckystrike
{
    meta:
        description = "Detection patterns for the tool 'luckystrike' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "luckystrike"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A PowerShell based utility for the creation of malicious Office macro documents.
        // Reference: https://github.com/curi0usJack/luckystrike
        $string1 = /luckystrike\.ps1/ nocase ascii wide

    condition:
        any of them
}
