rule RedTeam_toolkit
{
    meta:
        description = "Detection patterns for the tool 'RedTeam_toolkit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RedTeam_toolkit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fast and customizable vulnerability scanner For JIRA written in Python
        // Reference: https://github.com/MayankPandey01/Jira-Lens
        $string1 = /.{0,1000}\/Jira\-Lens\/.{0,1000}/ nocase ascii wide
        // Description: Red Team Toolkit is an Open-Source Django Offensive Web-App which is keeping the useful offensive tools used in the red-teaming together
        // Reference: https://github.com/signorrayan/RedTeam_toolkit
        $string2 = /.{0,1000}\/RedTeam_toolkit.{0,1000}/ nocase ascii wide
        // Description: Red Team Toolkit is an Open-Source Django Offensive Web-App which is keeping the useful offensive tools used in the red-teaming together
        // Reference: https://github.com/signorrayan/RedTeam_toolkit
        $string3 = /.{0,1000}cvescanner\.py.{0,1000}/ nocase ascii wide
        // Description: Red Team Toolkit is an Open-Source Django Offensive Web-App which is keeping the useful offensive tools used in the red-teaming together
        // Reference: https://github.com/signorrayan/RedTeam_toolkit
        $string4 = /.{0,1000}dirscanner\.py.{0,1000}/ nocase ascii wide
        // Description: Red Team Toolkit is an Open-Source Django Offensive Web-App which is keeping the useful offensive tools used in the red-teaming together
        // Reference: https://github.com/signorrayan/RedTeam_toolkit
        $string5 = /.{0,1000}rdpbrute\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
