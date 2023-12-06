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
        $string1 = /\sinstall\snikto/ nocase ascii wide
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string2 = /\snikto\.pl\s/ nocase ascii wide
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string3 = /\/nikto\.git/ nocase ascii wide
        // Description: Nikto web scanner tool
        // Reference: https://github.com/sullo/nikto
        $string4 = /\/nikto\.pl/ nocase ascii wide
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string5 = /\/nikto\.pl/ nocase ascii wide
        // Description: Nikto web scanner tool
        // Reference: https://github.com/sullo/nikto
        $string6 = /\/sullo\/nikto/ nocase ascii wide
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string7 = /nikto\s\-C\sall\s/ nocase ascii wide
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string8 = /nikto\/program/ nocase ascii wide
        // Description: Nikto web scanner tool
        // Reference: https://github.com/sullo/nikto
        $string9 = /perl\snikto\.pl\s\-h/ nocase ascii wide
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string10 = /program\/replay\.pl/ nocase ascii wide
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string11 = /sullo\/nikto/ nocase ascii wide
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string12 = /nikto\s\-/ nocase ascii wide

    condition:
        any of them
}
