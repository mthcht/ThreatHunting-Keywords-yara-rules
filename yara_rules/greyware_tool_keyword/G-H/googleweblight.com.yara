rule googleweblight_com
{
    meta:
        description = "Detection patterns for the tool 'googleweblight.com' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "googleweblight.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Open Redirect vulnerability being exploited by threat actors in Google Web Light
        // Reference: https://x.com/1ZRR4H/status/1723062039680000255
        $string1 = /https\:\/\/googleweblight\.com\/i\?u\=.{0,1000}ipfs\..{0,1000}\.html/ nocase ascii wide

    condition:
        any of them
}
