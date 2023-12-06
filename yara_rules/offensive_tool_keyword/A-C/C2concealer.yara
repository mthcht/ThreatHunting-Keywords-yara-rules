rule C2concealer
{
    meta:
        description = "Detection patterns for the tool 'C2concealer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C2concealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C2concealer is a command line tool that generates randomized C2 malleable profiles for use in Cobalt Strike.
        // Reference: https://github.com/RedSiege/C2concealer
        $string1 = /\s\-t\sC2concealer\s/ nocase ascii wide
        // Description: C2concealer is a command line tool that generates randomized C2 malleable profiles for use in Cobalt Strike.
        // Reference: https://github.com/RedSiege/C2concealer
        $string2 = /\/C2concealer/ nocase ascii wide
        // Description: C2concealer is a command line tool that generates randomized C2 malleable profiles for use in Cobalt Strike.
        // Reference: https://github.com/RedSiege/C2concealer
        $string3 = /\/cobaltstrike\/c2lint/ nocase ascii wide
        // Description: C2concealer is a command line tool that generates randomized C2 malleable profiles for use in Cobalt Strike.
        // Reference: https://github.com/RedSiege/C2concealer
        $string4 = /\/usr\/share\/cobaltstrike\// nocase ascii wide
        // Description: C2concealer is a command line tool that generates randomized C2 malleable profiles for use in Cobalt Strike.
        // Reference: https://github.com/RedSiege/C2concealer
        $string5 = /\\C2concealer/ nocase ascii wide
        // Description: C2concealer is a command line tool that generates randomized C2 malleable profiles for use in Cobalt Strike.
        // Reference: https://github.com/RedSiege/C2concealer
        $string6 = /C2concealer\s\-/ nocase ascii wide
        // Description: C2concealer is a command line tool that generates randomized C2 malleable profiles for use in Cobalt Strike.
        // Reference: https://github.com/RedSiege/C2concealer
        $string7 = /C2concealer\-master/ nocase ascii wide
        // Description: C2concealer is a command line tool that generates randomized C2 malleable profiles for use in Cobalt Strike.
        // Reference: https://github.com/RedSiege/C2concealer
        $string8 = /malleable\-c2\-randomizer\.py/ nocase ascii wide

    condition:
        any of them
}
