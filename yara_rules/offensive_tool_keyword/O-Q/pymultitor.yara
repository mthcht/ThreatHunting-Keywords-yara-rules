rule pymultitor
{
    meta:
        description = "Detection patterns for the tool 'pymultitor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pymultitor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Python Multi Threaded Tor Proxy. Did you ever want to be at two different places at the same time?   When I asked myself this question. I actually started developing this solution in my mind. While performing penetration tests there are often problems caused by security devices that block the attacking IP
        // Reference: https://github.com/realgam3/pymultitor
        $string1 = /pymultitor/ nocase ascii wide

    condition:
        any of them
}
