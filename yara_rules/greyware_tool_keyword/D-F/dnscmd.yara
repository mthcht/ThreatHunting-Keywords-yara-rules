rule dnscmd
{
    meta:
        description = "Detection patterns for the tool 'dnscmd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnscmd"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: the actor gather information about the target environment
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string1 = /dnscmd\s\.\s\/enumrecords\s\/zone\s/ nocase ascii wide
        // Description: the actor gather information about the target environment
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string2 = /dnscmd\s\.\s\/enumzones/ nocase ascii wide

    condition:
        any of them
}
