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
        $string1 = /.{0,1000}\/SilentMoonwalk\.git.{0,1000}/ nocase ascii wide
        // Description: PoC Implementation of a fully dynamic call stack spoofer
        // Reference: https://github.com/klezVirus/SilentMoonwalk
        $string2 = /.{0,1000}E11DC25D\-E96D\-495D\-8968\-1BA09C95B673.{0,1000}/ nocase ascii wide
        // Description: PoC Implementation of a fully dynamic call stack spoofer
        // Reference: https://github.com/klezVirus/SilentMoonwalk
        $string3 = /.{0,1000}klezVirus\/SilentMoonwalk.{0,1000}/ nocase ascii wide
        // Description: PoC Implementation of a fully dynamic call stack spoofer
        // Reference: https://github.com/klezVirus/SilentMoonwalk
        $string4 = /.{0,1000}SilentMoonwalk\.cpp.{0,1000}/ nocase ascii wide
        // Description: PoC Implementation of a fully dynamic call stack spoofer
        // Reference: https://github.com/klezVirus/SilentMoonwalk
        $string5 = /.{0,1000}SilentMoonwalk\.exe.{0,1000}/ nocase ascii wide
        // Description: PoC Implementation of a fully dynamic call stack spoofer
        // Reference: https://github.com/klezVirus/SilentMoonwalk
        $string6 = /.{0,1000}SilentMoonwalk\.sln.{0,1000}/ nocase ascii wide
        // Description: PoC Implementation of a fully dynamic call stack spoofer
        // Reference: https://github.com/klezVirus/SilentMoonwalk
        $string7 = /.{0,1000}SilentMoonwalk\-master.{0,1000}/ nocase ascii wide
        // Description: PoC Implementation of a fully dynamic call stack spoofer
        // Reference: https://github.com/klezVirus/SilentMoonwalk
        $string8 = /.{0,1000}UnwindInspector\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
