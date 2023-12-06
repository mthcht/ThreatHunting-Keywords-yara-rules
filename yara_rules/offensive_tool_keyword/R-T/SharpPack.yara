rule SharpPack
{
    meta:
        description = "Detection patterns for the tool 'SharpPack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpPack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpPack is a toolkit for insider threat assessments that lets you defeat application whitelisting to execute arbitrary DotNet and PowerShell tools.
        // Reference: https://github.com/mdsecactivebreach/SharpPack
        $string1 = /SharpPack/ nocase ascii wide

    condition:
        any of them
}
