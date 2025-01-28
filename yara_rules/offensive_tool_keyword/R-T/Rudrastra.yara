rule Rudrastra
{
    meta:
        description = "Detection patterns for the tool 'Rudrastra' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Rudrastra"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Make a Fake wireless access point aka Evil Twin
        // Reference: https://github.com/SxNade/Rudrastra
        $string1 = /\/Rudrastra\.git/ nocase ascii wide
        // Description: Make a Fake wireless access point aka Evil Twin
        // Reference: https://github.com/SxNade/Rudrastra
        $string2 = "aircrack-ng" nocase ascii wide
        // Description: Make a Fake wireless access point aka Evil Twin
        // Reference: https://github.com/SxNade/Rudrastra
        $string3 = /fake_ap\.py/ nocase ascii wide
        // Description: Make a Fake wireless access point aka Evil Twin
        // Reference: https://github.com/SxNade/Rudrastra
        $string4 = "install macchanger" nocase ascii wide
        // Description: Make a Fake wireless access point aka Evil Twin
        // Reference: https://github.com/SxNade/Rudrastra
        $string5 = "macchanger -r" nocase ascii wide
        // Description: Make a Fake wireless access point aka Evil Twin
        // Reference: https://github.com/SxNade/Rudrastra
        $string6 = /Rudrastra\-main\.zip/ nocase ascii wide
        // Description: Make a Fake wireless access point aka Evil Twin
        // Reference: https://github.com/SxNade/Rudrastra
        $string7 = "SxNade/Rudrastra" nocase ascii wide

    condition:
        any of them
}
