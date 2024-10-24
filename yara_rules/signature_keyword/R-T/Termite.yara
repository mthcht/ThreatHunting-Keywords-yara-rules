rule Termite
{
    meta:
        description = "Detection patterns for the tool 'Termite' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Termite"
        rule_category = "signature_keyword"

    strings:
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string1 = /BKDR_TERMITE\.A/ nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string2 = /W32\/EarthWorm/ nocase ascii wide

    condition:
        any of them
}
