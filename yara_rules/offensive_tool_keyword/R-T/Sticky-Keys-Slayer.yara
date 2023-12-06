rule Sticky_Keys_Slayer
{
    meta:
        description = "Detection patterns for the tool 'Sticky-Keys-Slayer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sticky-Keys-Slayer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Scans for accessibility tools backdoors via RDP
        // Reference: https://github.com/linuz/Sticky-Keys-Slayer
        $string1 = /Sticky\-Keys\-Slayer/ nocase ascii wide

    condition:
        any of them
}
