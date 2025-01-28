rule diskshadow
{
    meta:
        description = "Detection patterns for the tool 'diskshadow' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "diskshadow"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: diskshadow.exe abused by attackers with a script to create a VSS on a DC or delete the shadow copies on the systems
        // Reference: https://x.com/SecurityAura/status/1869579192905703735
        $string1 = "diskshadow /s " nocase ascii wide
        // Description: List shadow copies using diskshadow
        // Reference: N/A
        $string2 = "diskshadow list shadows all" nocase ascii wide
        // Description: diskshadow.exe abused by attackers with a script to create a VSS on a DC or delete the shadow copies on the systems
        // Reference: https://x.com/SecurityAura/status/1869579192905703735
        $string3 = "diskshadow -s " nocase ascii wide
        // Description: diskshadow.exe abused by attackers with a script to create a VSS on a DC or delete the shadow copies on the systems
        // Reference: https://x.com/SecurityAura/status/1869579192905703735
        $string4 = /diskshadow\.exe\s\/s\s/ nocase ascii wide
        // Description: List shadow copies using diskshadow
        // Reference: N/A
        $string5 = /diskshadow\.exe\slist\sshadows\sall/ nocase ascii wide
        // Description: diskshadow.exe abused by attackers with a script to create a VSS on a DC or delete the shadow copies on the systems
        // Reference: https://x.com/SecurityAura/status/1869579192905703735
        $string6 = /diskshadow\.exe\s\-s\s/ nocase ascii wide
        // Description: diskshadow.exe abused by attackers with a script to create a VSS on a DC or delete the shadow copies on the systems
        // Reference: https://x.com/SecurityAura/status/1869579192905703735
        $string7 = /diskshadow\.exe\\"\s\/s\s/ nocase ascii wide
        // Description: List shadow copies using diskshadow
        // Reference: N/A
        $string8 = /diskshadow\.exe\\"\slist\sshadows\sall/ nocase ascii wide
        // Description: diskshadow.exe abused by attackers with a script to create a VSS on a DC or delete the shadow copies on the systems
        // Reference: https://x.com/SecurityAura/status/1869579192905703735
        $string9 = /diskshadow\.exe\\"\s\-s\s/ nocase ascii wide

    condition:
        any of them
}
