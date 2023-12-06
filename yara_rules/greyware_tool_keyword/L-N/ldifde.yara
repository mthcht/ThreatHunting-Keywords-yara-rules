rule ldifde
{
    meta:
        description = "Detection patterns for the tool 'ldifde' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldifde"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: using ldifde.exe to export data from Active Directory to a .txt file in the Temp directory
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string1 = /ldifde\.exe\s\-f\s.{0,1000}\\temp\\.{0,1000}\.txt\s\-p\ssubtree/ nocase ascii wide

    condition:
        any of them
}
