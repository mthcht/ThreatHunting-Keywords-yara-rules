rule dnsteal
{
    meta:
        description = "Detection patterns for the tool 'dnsteal' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnsteal"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is a fake DNS server that allows you to stealthily extract files from a victim machine through DNS requests.
        // Reference: https://github.com/m57/dnsteal
        $string1 = /\/dnsteal/ nocase ascii wide
        // Description: This is a fake DNS server that allows you to stealthily extract files from a victim machine through DNS requests.
        // Reference: https://github.com/m57/dnsteal
        $string2 = /dnsteal\.git/ nocase ascii wide
        // Description: This is a fake DNS server that allows you to stealthily extract files from a victim machine through DNS requests.
        // Reference: https://github.com/m57/dnsteal
        $string3 = /dnsteal\.py/ nocase ascii wide
        // Description: This is a fake DNS server that allows you to stealthily extract files from a victim machine through DNS requests.
        // Reference: https://github.com/m57/dnsteal
        $string4 = /dnsteal\-master/ nocase ascii wide

    condition:
        any of them
}
