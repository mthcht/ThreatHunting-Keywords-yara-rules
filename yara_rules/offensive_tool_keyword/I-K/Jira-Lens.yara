rule Jira_Lens
{
    meta:
        description = "Detection patterns for the tool 'Jira-Lens' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Jira-Lens"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fast and customizable vulnerability scanner For JIRA written in Python
        // Reference: https://github.com/MayankPandey01/Jira-Lens
        $string1 = /\/Jira\-Lens\.git/ nocase ascii wide
        // Description: Fast and customizable vulnerability scanner For JIRA written in Python
        // Reference: https://github.com/MayankPandey01/Jira-Lens
        $string2 = /install\sJira\-Lens/ nocase ascii wide
        // Description: finds (non-standard) shares on hosts in the local domain
        // Reference: https://powersploit.readthedocs.io/en/stable/Recon/README/
        $string3 = /Invoke\-ShareFinder/ nocase ascii wide
        // Description: Fast and customizable vulnerability scanner For JIRA written in Python
        // Reference: https://github.com/MayankPandey01/Jira-Lens
        $string4 = /Jira\-Lens\.py/ nocase ascii wide
        // Description: Fast and customizable vulnerability scanner For JIRA written in Python
        // Reference: https://github.com/MayankPandey01/Jira-Lens
        $string5 = /MayankPandey01\/Jira\-Lens/ nocase ascii wide

    condition:
        any of them
}
