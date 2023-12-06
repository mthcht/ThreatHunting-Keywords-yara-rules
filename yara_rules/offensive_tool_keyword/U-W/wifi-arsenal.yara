rule wifi_arsenal
{
    meta:
        description = "Detection patterns for the tool 'wifi-arsenal' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifi-arsenal"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: github repo with all the wireless exploitation tools available
        // Reference: https://github.com/0x90/wifi-arsenal
        $string1 = /wifi\-arsenal/ nocase ascii wide

    condition:
        any of them
}
