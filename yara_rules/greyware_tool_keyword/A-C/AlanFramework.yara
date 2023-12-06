rule AlanFramework
{
    meta:
        description = "Detection patterns for the tool 'AlanFramework' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AlanFramework"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string1 = /http.{0,1000}:\/\/127\.0\.0\.1:8081/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string2 = /http.{0,1000}:\/\/localhost:8081/ nocase ascii wide

    condition:
        any of them
}
