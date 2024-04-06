rule slack
{
    meta:
        description = "Detection patterns for the tool 'slack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "slack"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: API usage of slack - creating channel - abused by multiple C2
        // Reference: https://github.com/mthcht/Purpleteam/blob/main/Detection/Threat%20Hunting/generic/C2_abusing_API_services.md
        $string1 = /https\:\/\/slack\.com\/api\/channels\.create/ nocase ascii wide

    condition:
        any of them
}
