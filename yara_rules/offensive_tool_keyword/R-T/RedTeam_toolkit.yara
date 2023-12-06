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
        $string1 = /\/Jira\-Lens\// nocase ascii wide
        // Description: Red Team Toolkit is an Open-Source Django Offensive Web-App which is keeping the useful offensive tools used in the red-teaming together
        // Reference: https://github.com/signorrayan/RedTeam_toolkit
        $string2 = /\/RedTeam_toolkit/ nocase ascii wide
        // Description: Red Team Toolkit is an Open-Source Django Offensive Web-App which is keeping the useful offensive tools used in the red-teaming together
        // Reference: https://github.com/signorrayan/RedTeam_toolkit
        $string3 = /cvescanner\.py/ nocase ascii wide
        // Description: Red Team Toolkit is an Open-Source Django Offensive Web-App which is keeping the useful offensive tools used in the red-teaming together
        // Reference: https://github.com/signorrayan/RedTeam_toolkit
        $string4 = /dirscanner\.py/ nocase ascii wide
        // Description: Red Team Toolkit is an Open-Source Django Offensive Web-App which is keeping the useful offensive tools used in the red-teaming together
        // Reference: https://github.com/signorrayan/RedTeam_toolkit
        $string5 = /rdpbrute\.py/ nocase ascii wide

    condition:
        any of them
}
