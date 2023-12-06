rule SilentMoonwalk
{
    meta:
        description = "Detection patterns for the tool 'SilentMoonwalk' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SilentMoonwalk"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PoC Implementation of a fully dynamic call stack spoofer
        // Reference: https://github.com/klezVirus/SilentMoonwalk
        $string1 = /\/SilentMoonwalk\.git/ nocase ascii wide
        // Description: PoC Implementation of a fully dynamic call stack spoofer
        // Reference: https://github.com/klezVirus/SilentMoonwalk
        $string2 = /E11DC25D\-E96D\-495D\-8968\-1BA09C95B673/ nocase ascii wide
        // Description: PoC Implementation of a fully dynamic call stack spoofer
        // Reference: https://github.com/klezVirus/SilentMoonwalk
        $string3 = /klezVirus\/SilentMoonwalk/ nocase ascii wide
        // Description: PoC Implementation of a fully dynamic call stack spoofer
        // Reference: https://github.com/klezVirus/SilentMoonwalk
        $string4 = /SilentMoonwalk\.cpp/ nocase ascii wide
        // Description: PoC Implementation of a fully dynamic call stack spoofer
        // Reference: https://github.com/klezVirus/SilentMoonwalk
        $string5 = /SilentMoonwalk\.exe/ nocase ascii wide
        // Description: PoC Implementation of a fully dynamic call stack spoofer
        // Reference: https://github.com/klezVirus/SilentMoonwalk
        $string6 = /SilentMoonwalk\.sln/ nocase ascii wide
        // Description: PoC Implementation of a fully dynamic call stack spoofer
        // Reference: https://github.com/klezVirus/SilentMoonwalk
        $string7 = /SilentMoonwalk\-master/ nocase ascii wide
        // Description: PoC Implementation of a fully dynamic call stack spoofer
        // Reference: https://github.com/klezVirus/SilentMoonwalk
        $string8 = /UnwindInspector\.exe/ nocase ascii wide

    condition:
        any of them
}
