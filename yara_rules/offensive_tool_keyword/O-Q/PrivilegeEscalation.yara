rule PrivilegeEscalation
{
    meta:
        description = "Detection patterns for the tool 'PrivilegeEscalation' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrivilegeEscalation"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This program is a very short batch file which allows you to run anything with admin rights without prompting user could be related to other tools using privsec methods
        // Reference: https://github.com/LouisVallat/PrivilegeEscalation
        $string1 = /PrivilegeEscalation/ nocase ascii wide

    condition:
        any of them
}
