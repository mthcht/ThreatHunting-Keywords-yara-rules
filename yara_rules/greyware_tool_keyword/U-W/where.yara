rule where
{
    meta:
        description = "Detection patterns for the tool 'where' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "where"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: threat actors searched for Active Directory related DLLs in directories
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string1 = /\swhere\s\/r\sC\:\\Windows\\WinSxS\\\s.{0,1000}Microsoft\.ActiveDirectory\.Management\.dll/ nocase ascii wide

    condition:
        any of them
}
