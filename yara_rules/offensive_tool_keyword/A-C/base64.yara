rule _base64
{
    meta:
        description = "Detection patterns for the tool 'base64' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "base64"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: start of an executable payload in base64
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/MockDirUACBypass
        $string1 = /TVqQAAMAAAAEAAAA/ nocase ascii wide

    condition:
        any of them
}
