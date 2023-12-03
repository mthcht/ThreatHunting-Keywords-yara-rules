rule JustEvadeBro
{
    meta:
        description = "Detection patterns for the tool 'JustEvadeBro' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "JustEvadeBro"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: JustEvadeBro a cheat sheet which will aid you through AMSI/AV evasion & bypasses.
        // Reference: https://github.com/sinfulz/JustEvadeBro
        $string1 = /.{0,1000}\spapacat\.ps1.{0,1000}/ nocase ascii wide
        // Description: JustEvadeBro a cheat sheet which will aid you through AMSI/AV evasion & bypasses.
        // Reference: https://github.com/sinfulz/JustEvadeBro
        $string2 = /.{0,1000}\/papacat\.zip.{0,1000}/ nocase ascii wide
        // Description: JustEvadeBro a cheat sheet which will aid you through AMSI/AV evasion & bypasses.
        // Reference: https://github.com/sinfulz/JustEvadeBro
        $string3 = /.{0,1000}\\papacat\.ps1.{0,1000}/ nocase ascii wide
        // Description: JustEvadeBro a cheat sheet which will aid you through AMSI/AV evasion & bypasses.
        // Reference: https://github.com/sinfulz/JustEvadeBro
        $string4 = /.{0,1000}\\papacat\.zip.{0,1000}/ nocase ascii wide
        // Description: JustEvadeBro a cheat sheet which will aid you through AMSI/AV evasion & bypasses.
        // Reference: https://github.com/sinfulz/JustEvadeBro
        $string5 = /.{0,1000}aQBlAHgAIAAoAE4AZwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMgAvAHIAZQB2AC4AcABzADEAJwApAA.{0,1000}/ nocase ascii wide
        // Description: JustEvadeBro a cheat sheet which will aid you through AMSI/AV evasion & bypasses.
        // Reference: https://github.com/sinfulz/JustEvadeBro
        $string6 = /.{0,1000}papacat\s\-l\s\-p\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
