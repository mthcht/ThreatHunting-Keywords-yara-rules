rule ghostsocks
{
    meta:
        description = "Detection patterns for the tool 'ghostsocks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ghostsocks"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string1 = /\.ghostsocks\.json/ nocase ascii wide
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string2 = /\/ghostsocks\.git/ nocase ascii wide
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string3 = /\\ghostsocks\-master/ nocase ascii wide
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string4 = "28625926a22131062b34670f36dafb312c2631b576bcfa0f9544994de77b6544" nocase ascii wide
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string5 = "ca94d5a554af633b96f7a6b0e4b8891b4a1e30812df356f7bc21e99dbce90d8e" nocase ascii wide
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string6 = "DefaultListenAddr = \":7448\"" nocase ascii wide
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string7 = "ghostsocks-local" nocase ascii wide
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string8 = "ghostsocks-server" nocase ascii wide
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string9 = "LemonSaaS/ghostsocks" nocase ascii wide

    condition:
        any of them
}
