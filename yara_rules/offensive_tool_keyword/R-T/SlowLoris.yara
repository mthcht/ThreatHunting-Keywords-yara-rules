rule SlowLoris
{
    meta:
        description = "Detection patterns for the tool 'SlowLoris' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SlowLoris"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Slowloris is basically an HTTP Denial of Service attack that affects threaded servers. It works like this
        // Reference: https://github.com/gkbrk/slowloris
        $string1 = /SlowLoris/ nocase ascii wide

    condition:
        any of them
}
