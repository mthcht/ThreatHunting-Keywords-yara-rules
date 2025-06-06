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
        $string1 = /\/pivotnacci\.git/ nocase ascii wide
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string2 = "/pivotnaccilib"
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string3 = "blackarrowsec/pivotnacci" nocase ascii wide
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string4 = /from\s\.socks\simport\sSocksNegotiator/ nocase ascii wide
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string5 = "install pivotnacci" nocase ascii wide
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string6 = "install pivotnacci" nocase ascii wide
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string7 = "pivotnacci  http" nocase ascii wide
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string8 = "pivotnacci -" nocase ascii wide
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string9 = /pivotnacci\s.{0,1000}\-\-polling\-interval/ nocase ascii wide
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string10 = /pivotnacci\/0\.0\.1/ nocase ascii wide
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string11 = /pivotnaccilib.{0,1000}socks/ nocase ascii wide
        // Description: A tool to make socks connections through HTTP agents
        // Reference: https://github.com/blackarrowsec/pivotnacci
        $string12 = "pivotnacci-master" nocase ascii wide

    condition:
        any of them
}
