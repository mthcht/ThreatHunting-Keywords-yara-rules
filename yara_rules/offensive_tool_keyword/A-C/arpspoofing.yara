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
        $string1 = /.{0,1000}\/luijait\/arpspoofing.{0,1000}/ nocase ascii wide
        // Description: arp spoofing scripts
        // Reference: https://github.com/luijait/arpspoofing
        $string2 = /.{0,1000}arpspoofing\.py\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
