rule LinEnum
{
    meta:
        description = "Detection patterns for the tool 'LinEnum' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LinEnum"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Scripted Local Linux Enumeration & Privilege Escalation Checks
        // Reference: https://github.com/rebootuser/LinEnum
        $string1 = /.{0,1000}\/LinEnum\.git.{0,1000}/ nocase ascii wide
        // Description: Scripted Local Linux Enumeration & Privilege Escalation Checks
        // Reference: https://github.com/rebootuser/LinEnum
        $string2 = /.{0,1000}\/LinEnum\/.{0,1000}/ nocase ascii wide
        // Description: Scripted Local Linux Enumeration & Privilege Escalation Checks
        // Reference: https://github.com/rebootuser/LinEnum
        $string3 = /.{0,1000}LinEnum\.sh.{0,1000}/ nocase ascii wide
        // Description: Scripted Local Linux Enumeration & Privilege Escalation Checks
        // Reference: https://github.com/rebootuser/LinEnum
        $string4 = /.{0,1000}LinEnum\-master\.ip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
