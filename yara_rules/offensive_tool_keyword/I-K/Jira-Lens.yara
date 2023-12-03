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
        $string1 = /.{0,1000}\/Jira\-Lens\.git.{0,1000}/ nocase ascii wide
        // Description: Fast and customizable vulnerability scanner For JIRA written in Python
        // Reference: https://github.com/MayankPandey01/Jira-Lens
        $string2 = /.{0,1000}install\sJira\-Lens.{0,1000}/ nocase ascii wide
        // Description: finds (non-standard) shares on hosts in the local domain
        // Reference: https://powersploit.readthedocs.io/en/stable/Recon/README/
        $string3 = /.{0,1000}Invoke\-ShareFinder.{0,1000}/ nocase ascii wide
        // Description: Fast and customizable vulnerability scanner For JIRA written in Python
        // Reference: https://github.com/MayankPandey01/Jira-Lens
        $string4 = /.{0,1000}Jira\-Lens\.py.{0,1000}/ nocase ascii wide
        // Description: Fast and customizable vulnerability scanner For JIRA written in Python
        // Reference: https://github.com/MayankPandey01/Jira-Lens
        $string5 = /.{0,1000}MayankPandey01\/Jira\-Lens.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
