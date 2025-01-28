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
        $string1 = /\/LinEnum\.git/
        // Description: Scripted Local Linux Enumeration & Privilege Escalation Checks
        // Reference: https://github.com/rebootuser/LinEnum
        $string2 = "/LinEnum/"
        // Description: Scripted Local Linux Enumeration & Privilege Escalation Checks
        // Reference: https://github.com/rebootuser/LinEnum
        $string3 = /LinEnum\.sh/
        // Description: Scripted Local Linux Enumeration & Privilege Escalation Checks
        // Reference: https://github.com/rebootuser/LinEnum
        $string4 = /LinEnum\-master\.ip/

    condition:
        any of them
}
