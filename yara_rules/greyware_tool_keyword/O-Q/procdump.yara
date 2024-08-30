rule procdump
{
    meta:
        description = "Detection patterns for the tool 'procdump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "procdump"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Dump files might contain sensitive data and are often created as part of debugging processes or by attackers exfiltrating data. Users\Public should not be used
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string1 = /\\Users\\Public\\.{0,1000}\.dmp/ nocase ascii wide

    condition:
        any of them
}
