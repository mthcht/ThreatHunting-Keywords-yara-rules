rule Gorsair
{
    meta:
        description = "Detection patterns for the tool 'Gorsair' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Gorsair"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Gorsair hacks its way into remote docker containers that expose their APIs
        // Reference: https://github.com/Ullaakut/Gorsair
        $string1 = /.{0,1000}\/bin\/gorsair\s.{0,1000}/ nocase ascii wide
        // Description: Gorsair hacks its way into remote docker containers that expose their APIs
        // Reference: https://github.com/Ullaakut/Gorsair
        $string2 = /.{0,1000}\/gorsair\.go.{0,1000}/ nocase ascii wide
        // Description: Gorsair hacks its way into remote docker containers that expose their APIs
        // Reference: https://github.com/Ullaakut/Gorsair
        $string3 = /.{0,1000}gorsair\s\-t\s.{0,1000}/ nocase ascii wide
        // Description: Gorsair hacks its way into remote docker containers that expose their APIs
        // Reference: https://github.com/Ullaakut/Gorsair
        $string4 = /.{0,1000}Ullaakut\/Gorsair.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
