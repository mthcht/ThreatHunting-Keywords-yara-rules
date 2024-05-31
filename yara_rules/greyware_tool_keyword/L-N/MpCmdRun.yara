rule MpCmdRun
{
    meta:
        description = "Detection patterns for the tool 'MpCmdRun' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MpCmdRun"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Defense evasion technique disable windows defender
        // Reference: N/A
        $string1 = /MpCmdRun\.exe.{0,1000}\s\-disable/ nocase ascii wide
        // Description: Wipe currently stored definitions
        // Reference: N/A
        $string2 = /MpCmdRun\.exe.{0,1000}\s\-RemoveDefinitions\s\-All/ nocase ascii wide

    condition:
        any of them
}
