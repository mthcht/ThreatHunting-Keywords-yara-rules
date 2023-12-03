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
        $string1 = /.{0,1000}\steamstracker\.py.{0,1000}/ nocase ascii wide
        // Description: using graph proxy to monitor teams user presence
        // Reference: https://github.com/nyxgeek/teamstracker
        $string2 = /.{0,1000}\/teamstracker\.db.{0,1000}/ nocase ascii wide
        // Description: using graph proxy to monitor teams user presence
        // Reference: https://github.com/nyxgeek/teamstracker
        $string3 = /.{0,1000}\/teamstracker\.git.{0,1000}/ nocase ascii wide
        // Description: using graph proxy to monitor teams user presence
        // Reference: https://github.com/nyxgeek/teamstracker
        $string4 = /.{0,1000}\/teamstracker\.py.{0,1000}/ nocase ascii wide
        // Description: using graph proxy to monitor teams user presence
        // Reference: https://github.com/nyxgeek/teamstracker
        $string5 = /.{0,1000}\\teamstracker\.py.{0,1000}/ nocase ascii wide
        // Description: using graph proxy to monitor teams user presence
        // Reference: https://github.com/nyxgeek/teamstracker
        $string6 = /.{0,1000}nyxgeek\/teamstracker.{0,1000}/ nocase ascii wide
        // Description: using graph proxy to monitor teams user presence
        // Reference: https://github.com/nyxgeek/teamstracker
        $string7 = /.{0,1000}teamstracker\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
