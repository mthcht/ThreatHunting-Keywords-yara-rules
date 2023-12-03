rule pivotnacci
{
    meta:
        description = "Detection patterns for the tool 'pivotnacci' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pivotnacci"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string1 = /.{0,1000}\/pivotnacci\.git.{0,1000}/ nocase ascii wide
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string2 = /.{0,1000}\/pivotnaccilib.{0,1000}/ nocase ascii wide
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string3 = /.{0,1000}blackarrowsec\/pivotnacci.{0,1000}/ nocase ascii wide
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string4 = /.{0,1000}install\spivotnacci.{0,1000}/ nocase ascii wide
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string5 = /.{0,1000}pivotnacci\s\shttp.{0,1000}/ nocase ascii wide
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string6 = /.{0,1000}pivotnacci\s\-.{0,1000}/ nocase ascii wide
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string7 = /.{0,1000}pivotnacci\s.{0,1000}\-\-polling\-interval.{0,1000}/ nocase ascii wide
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string8 = /.{0,1000}pivotnacci\/0\.0\.1.{0,1000}/ nocase ascii wide
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string9 = /.{0,1000}pivotnacci\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
