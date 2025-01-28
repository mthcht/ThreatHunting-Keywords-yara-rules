rule TrueSocks
{
    meta:
        description = "Detection patterns for the tool 'TrueSocks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TrueSocks"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Simple API for buying renting and managing proxies
        // Reference: https://github.com/c0dn/truesocks_rs
        $string1 = /\/truesocks_rs\.git/ nocase ascii wide
        // Description: Simple API for buying renting and managing proxies
        // Reference: https://github.com/c0dn/truesocks_rs
        $string2 = /api\.truesocks\.net/ nocase ascii wide
        // Description: Simple API for buying renting and managing proxies
        // Reference: https://github.com/c0dn/truesocks_rs
        $string3 = "c0dn/truesocks_rs" nocase ascii wide

    condition:
        any of them
}
