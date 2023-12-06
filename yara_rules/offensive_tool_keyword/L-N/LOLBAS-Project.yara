rule LOLBAS_Project
{
    meta:
        description = "Detection patterns for the tool 'LOLBAS-Project' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LOLBAS-Project"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Living Off The Land Binaries and Scripts (and also Libraries) malicious use of  legitimate tool
        // Reference: https://lolbas-project.github.io/
        $string1 = /LOLBAS\-Project/ nocase ascii wide

    condition:
        any of them
}
