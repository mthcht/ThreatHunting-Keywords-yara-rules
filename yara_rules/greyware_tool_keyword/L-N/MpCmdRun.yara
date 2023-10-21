rule MpCmdRun
{
    meta:
        description = "Detection patterns for the tool 'MpCmdRun' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MpCmdRun"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Wipe currently stored definitions
        // Reference: N/A
        $string1 = /MpCmdRun\.exe\s\-RemoveDefinitions\s\-All/ nocase ascii wide
        // Description: Defense evasion technique disable windows defender
        // Reference: N/A
        $string2 = /MpCmdRun\.exe.*\s\-disable/ nocase ascii wide

    condition:
        any of them
}