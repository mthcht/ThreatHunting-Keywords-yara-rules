rule _4shared_com
{
    meta:
        description = "Detection patterns for the tool '4shared.com' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "4shared.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Uploading on 4shared.com
        // Reference: 4shared.com
        $string1 = /4shared\.com\/.{0,1000}upload/ nocase ascii wide
        // Description: Downloading a file from 4shared.com
        // Reference: 4shared.com
        $string2 = /https\:\/\/www\.4shared\.com\/get\// nocase ascii wide

    condition:
        any of them
}
