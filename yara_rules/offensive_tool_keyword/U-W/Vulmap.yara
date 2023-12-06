rule Vulmap
{
    meta:
        description = "Detection patterns for the tool 'Vulmap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Vulmap"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Vulmap is an open-source online local vulnerability scanner project. It consists of online local vulnerability scanning programs for Windows and Linux operating systems. These scripts can be used for defensive and offensive purposes. It is possible to make vulnerability assessments using these scripts. Also. they can be used for privilege escalation by pentesters/red teamers.
        // Reference: https://github.com/vulmon/Vulmap
        $string1 = /vulmon.{0,1000}Vulmap/ nocase ascii wide

    condition:
        any of them
}
