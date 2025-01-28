rule ghostsocks
{
    meta:
        description = "Detection patterns for the tool 'ghostsocks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ghostsocks"
        rule_category = "signature_keyword"

    strings:
        // Description: SOCKS5 proxy based on lightsocks
        // Reference: https://github.com/LemonSaaS/ghostsocks
        $string1 = "Trojan:Win32/GhostSocks" nocase ascii wide

    condition:
        any of them
}
