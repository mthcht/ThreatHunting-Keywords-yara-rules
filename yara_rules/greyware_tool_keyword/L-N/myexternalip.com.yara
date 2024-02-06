rule myexternalip_com
{
    meta:
        description = "Detection patterns for the tool 'myexternalip.com' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "myexternalip.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: return external ip address
        // Reference: https://myexternalip.com/raw
        $string1 = /https\:\/\/myexternalip\.com\/raw/ nocase ascii wide

    condition:
        any of them
}
