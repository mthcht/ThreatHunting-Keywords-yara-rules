rule schtasks
{
    meta:
        description = "Detection patterns for the tool 'schtasks' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "schtasks"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: view detailed information about all the scheduled tasks.
        // Reference: N/A
        $string1 = /.{0,1000}schtasks\s\/query\s\/v\s\/fo\sLIST.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
