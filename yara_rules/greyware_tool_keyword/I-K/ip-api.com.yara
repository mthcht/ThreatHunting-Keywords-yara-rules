rule ip_api_com
{
    meta:
        description = "Detection patterns for the tool 'ip-api.com' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ip-api.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: get public ip address
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string1 = /www\.ip\-api\.com/ nocase ascii wide

    condition:
        any of them
}
