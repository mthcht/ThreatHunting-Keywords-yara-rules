rule RasmanPotato
{
    meta:
        description = "Detection patterns for the tool 'RasmanPotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RasmanPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string1 = /.{0,1000}\srasman\.exe.{0,1000}/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string2 = /.{0,1000}\/rasman\.exe.{0,1000}/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string3 = /.{0,1000}\/RasmanPotato.{0,1000}/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string4 = /.{0,1000}\\rasman\.exe.{0,1000}/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string5 = /.{0,1000}\\RasmanPotato.{0,1000}/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string6 = /.{0,1000}anypotato\.exe.{0,1000}/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string7 = /.{0,1000}magicRasMan.{0,1000}/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string8 = /.{0,1000}rasman.{0,1000}whoami.{0,1000}/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string9 = /.{0,1000}RasMan\.cpp.{0,1000}/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string10 = /.{0,1000}RasMan\.sln.{0,1000}/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string11 = /.{0,1000}RasMan\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string12 = /.{0,1000}rasman_c\.c.{0,1000}/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string13 = /.{0,1000}rasman_h\.h.{0,1000}/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string14 = /.{0,1000}RasmanPotato\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
