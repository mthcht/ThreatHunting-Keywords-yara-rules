rule pysoxy
{
    meta:
        description = "Detection patterns for the tool 'pysoxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pysoxy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A small Socks5 Proxy Server in Python
        // Reference: https://github.com/MisterDaneel/pysoxy
        $string1 = /\/pysoxy\.git/ nocase ascii wide
        // Description: A small Socks5 Proxy Server in Python
        // Reference: https://github.com/MisterDaneel/pysoxy
        $string2 = /\/pysoxy\.py/ nocase ascii wide
        // Description: A small Socks5 Proxy Server in Python
        // Reference: https://github.com/MisterDaneel/pysoxy
        $string3 = /\\pysoxy\.py/ nocase ascii wide
        // Description: A small Socks5 Proxy Server in Python
        // Reference: https://github.com/MisterDaneel/pysoxy
        $string4 = /MisterDaneel\/pysoxy/ nocase ascii wide
        // Description: A small Socks5 Proxy Server in Python
        // Reference: https://github.com/MisterDaneel/pysoxy
        $string5 = /pysoxy\-master/ nocase ascii wide

    condition:
        any of them
}
