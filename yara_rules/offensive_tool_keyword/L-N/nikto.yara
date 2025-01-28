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
        $string1 = " install nikto"
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string2 = /\snikto\.pl\s/
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string3 = /\/nikto\.git/
        // Description: Nikto web scanner tool
        // Reference: https://github.com/sullo/nikto
        $string4 = /\/nikto\.pl/
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string5 = /\/nikto\.pl/
        // Description: Nikto web scanner tool
        // Reference: https://github.com/sullo/nikto
        $string6 = "/sullo/nikto"
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string7 = "nikto -C all "
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string8 = "nikto/program"
        // Description: Nikto web scanner tool
        // Reference: https://github.com/sullo/nikto
        $string9 = /perl\snikto\.pl\s\-h/
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string10 = /program\/replay\.pl/
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string11 = "sullo/nikto"
        // Description: Nikto web server scanner
        // Reference: https://github.com/sullo/nikto
        $string12 = "nikto -"

    condition:
        any of them
}
