rule kismet
{
    meta:
        description = "Detection patterns for the tool 'kismet' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kismet"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Kismet is a wireless network and device detector. sniffer. wardriving tool. and WIDS (wireless intrusion detection) framework.
        // Reference: https://github.com/kismetwireless/kismet
        $string1 = /\/kismet/ nocase ascii wide
        // Description: Kismet is a wireless network and device detector. sniffer. wardriving tool. and WIDS (wireless intrusion detection) framework.
        // Reference: https://github.com/kismetwireless/kismet
        $string2 = /\/kismetwireless\// nocase ascii wide

    condition:
        any of them
}
