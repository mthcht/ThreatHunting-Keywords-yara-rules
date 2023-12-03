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
        $string1 = /.{0,1000}\s\-t\sC2concealer\s.{0,1000}/ nocase ascii wide
        // Description: C2concealer is a command line tool that generates randomized C2 malleable profiles for use in Cobalt Strike.
        // Reference: https://github.com/RedSiege/C2concealer
        $string2 = /.{0,1000}\/C2concealer.{0,1000}/ nocase ascii wide
        // Description: C2concealer is a command line tool that generates randomized C2 malleable profiles for use in Cobalt Strike.
        // Reference: https://github.com/RedSiege/C2concealer
        $string3 = /.{0,1000}\/cobaltstrike\/c2lint.{0,1000}/ nocase ascii wide
        // Description: C2concealer is a command line tool that generates randomized C2 malleable profiles for use in Cobalt Strike.
        // Reference: https://github.com/RedSiege/C2concealer
        $string4 = /.{0,1000}\/usr\/share\/cobaltstrike\/.{0,1000}/ nocase ascii wide
        // Description: C2concealer is a command line tool that generates randomized C2 malleable profiles for use in Cobalt Strike.
        // Reference: https://github.com/RedSiege/C2concealer
        $string5 = /.{0,1000}\\C2concealer.{0,1000}/ nocase ascii wide
        // Description: C2concealer is a command line tool that generates randomized C2 malleable profiles for use in Cobalt Strike.
        // Reference: https://github.com/RedSiege/C2concealer
        $string6 = /.{0,1000}C2concealer\s\-.{0,1000}/ nocase ascii wide
        // Description: C2concealer is a command line tool that generates randomized C2 malleable profiles for use in Cobalt Strike.
        // Reference: https://github.com/RedSiege/C2concealer
        $string7 = /.{0,1000}C2concealer\-master.{0,1000}/ nocase ascii wide
        // Description: C2concealer is a command line tool that generates randomized C2 malleable profiles for use in Cobalt Strike.
        // Reference: https://github.com/RedSiege/C2concealer
        $string8 = /.{0,1000}malleable\-c2\-randomizer\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
