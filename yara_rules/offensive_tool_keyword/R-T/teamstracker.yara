rule teamstracker
{
    meta:
        description = "Detection patterns for the tool 'teamstracker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "teamstracker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: using graph proxy to monitor teams user presence
        // Reference: https://github.com/nyxgeek/teamstracker
        $string1 = /\steamstracker\.py/ nocase ascii wide
        // Description: using graph proxy to monitor teams user presence
        // Reference: https://github.com/nyxgeek/teamstracker
        $string2 = /\/teamstracker\.db/ nocase ascii wide
        // Description: using graph proxy to monitor teams user presence
        // Reference: https://github.com/nyxgeek/teamstracker
        $string3 = /\/teamstracker\.git/ nocase ascii wide
        // Description: using graph proxy to monitor teams user presence
        // Reference: https://github.com/nyxgeek/teamstracker
        $string4 = /\/teamstracker\.py/ nocase ascii wide
        // Description: using graph proxy to monitor teams user presence
        // Reference: https://github.com/nyxgeek/teamstracker
        $string5 = /\\teamstracker\.py/ nocase ascii wide
        // Description: using graph proxy to monitor teams user presence
        // Reference: https://github.com/nyxgeek/teamstracker
        $string6 = /nyxgeek\/teamstracker/ nocase ascii wide
        // Description: using graph proxy to monitor teams user presence
        // Reference: https://github.com/nyxgeek/teamstracker
        $string7 = /teamstracker\-main/ nocase ascii wide

    condition:
        any of them
}
