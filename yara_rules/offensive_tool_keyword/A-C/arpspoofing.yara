rule arpspoofing
{
    meta:
        description = "Detection patterns for the tool 'arpspoofing' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "arpspoofing"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: arp spoofing scripts
        // Reference: https://github.com/luijait/arpspoofing
        $string1 = /\/luijait\/arpspoofing/ nocase ascii wide
        // Description: arp spoofing scripts
        // Reference: https://github.com/luijait/arpspoofing
        $string2 = /arpspoofing\.py\s/ nocase ascii wide

    condition:
        any of them
}
