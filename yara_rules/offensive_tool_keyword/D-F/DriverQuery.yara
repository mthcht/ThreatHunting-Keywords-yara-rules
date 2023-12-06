rule DriverQuery
{
    meta:
        description = "Detection patterns for the tool 'DriverQuery' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DriverQuery"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Collect details about drivers on the system and optionally filter to find only ones not signed by Microsoft
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/DriverQuery
        $string1 = /\[\+\]\sEnumerating\sdriver\sservices\.\.\./ nocase ascii wide
        // Description: Collect details about drivers on the system and optionally filter to find only ones not signed by Microsoft
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/DriverQuery
        $string2 = /DriverQuery\.exe\sno\-msft/ nocase ascii wide
        // Description: Collect details about drivers on the system and optionally filter to find only ones not signed by Microsoft
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/DriverQuery
        $string3 = /OffensiveCSharp.{0,1000}DriverQuery/ nocase ascii wide

    condition:
        any of them
}
