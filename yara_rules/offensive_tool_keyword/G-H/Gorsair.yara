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
        $string1 = /\/bin\/gorsair\s/ nocase ascii wide
        // Description: Gorsair hacks its way into remote docker containers that expose their APIs
        // Reference: https://github.com/Ullaakut/Gorsair
        $string2 = /\/gorsair\.go/ nocase ascii wide
        // Description: Gorsair hacks its way into remote docker containers that expose their APIs
        // Reference: https://github.com/Ullaakut/Gorsair
        $string3 = /gorsair\s\-t\s/ nocase ascii wide
        // Description: Gorsair hacks its way into remote docker containers that expose their APIs
        // Reference: https://github.com/Ullaakut/Gorsair
        $string4 = /Ullaakut\/Gorsair/ nocase ascii wide

    condition:
        any of them
}
