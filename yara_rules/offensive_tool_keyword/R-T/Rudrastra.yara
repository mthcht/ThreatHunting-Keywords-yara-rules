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
        $string1 = /.{0,1000}\/Rudrastra\.git.{0,1000}/ nocase ascii wide
        // Description: Make a Fake wireless access point aka Evil Twin
        // Reference: https://github.com/SxNade/Rudrastra
        $string2 = /.{0,1000}aircrack\-ng.{0,1000}/ nocase ascii wide
        // Description: Make a Fake wireless access point aka Evil Twin
        // Reference: https://github.com/SxNade/Rudrastra
        $string3 = /.{0,1000}fake_ap\.py.{0,1000}/ nocase ascii wide
        // Description: Make a Fake wireless access point aka Evil Twin
        // Reference: https://github.com/SxNade/Rudrastra
        $string4 = /.{0,1000}install\smacchanger.{0,1000}/ nocase ascii wide
        // Description: Make a Fake wireless access point aka Evil Twin
        // Reference: https://github.com/SxNade/Rudrastra
        $string5 = /.{0,1000}macchanger\s\-r.{0,1000}/ nocase ascii wide
        // Description: Make a Fake wireless access point aka Evil Twin
        // Reference: https://github.com/SxNade/Rudrastra
        $string6 = /.{0,1000}Rudrastra\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: Make a Fake wireless access point aka Evil Twin
        // Reference: https://github.com/SxNade/Rudrastra
        $string7 = /.{0,1000}SxNade\/Rudrastra.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
