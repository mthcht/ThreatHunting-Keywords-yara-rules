rule SharpShooter
{
    meta:
        description = "Detection patterns for the tool 'SharpShooter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpShooter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string1 = /SharpShooter/ nocase ascii wide

    condition:
        any of them
}
