rule dnsmorph
{
    meta:
        description = "Detection patterns for the tool 'dnsmorph' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnsmorph"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DNSMORPH is a domain name permutation engine. inspired by dnstwist. It is written in Go making for a compact and very fast tool. It robustly handles any domain or subdomain supplied and provides a number of configuration options to tune permutation runs.
        // Reference: https://github.com/netevert/dnsmorph
        $string1 = /dnsmorph/ nocase ascii wide

    condition:
        any of them
}
