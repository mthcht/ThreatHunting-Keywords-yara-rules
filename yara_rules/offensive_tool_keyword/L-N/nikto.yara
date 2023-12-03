rule nikto
{
    meta:
        description = "Detection patterns for the tool 'nikto' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nikto"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string1 = /.{0,1000}\sinstall\snikto.{0,1000}/ nocase ascii wide
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string2 = /.{0,1000}\snikto\.pl\s.{0,1000}/ nocase ascii wide
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string3 = /.{0,1000}\/nikto\.git.{0,1000}/ nocase ascii wide
        // Description: Nikto web scanner tool
        // Reference: https://github.com/sullo/nikto
        $string4 = /.{0,1000}\/nikto\.pl.{0,1000}/ nocase ascii wide
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string5 = /.{0,1000}\/nikto\.pl.{0,1000}/ nocase ascii wide
        // Description: Nikto web scanner tool
        // Reference: https://github.com/sullo/nikto
        $string6 = /.{0,1000}\/sullo\/nikto.{0,1000}/ nocase ascii wide
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string7 = /.{0,1000}nikto\s\-C\sall\s.{0,1000}/ nocase ascii wide
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string8 = /.{0,1000}nikto\/program.{0,1000}/ nocase ascii wide
        // Description: Nikto web scanner tool
        // Reference: https://github.com/sullo/nikto
        $string9 = /.{0,1000}perl\snikto\.pl\s\-h.{0,1000}/ nocase ascii wide
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string10 = /.{0,1000}program\/replay\.pl.{0,1000}/ nocase ascii wide
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string11 = /.{0,1000}sullo\/nikto.{0,1000}/ nocase ascii wide
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string12 = /nikto\s\-.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
