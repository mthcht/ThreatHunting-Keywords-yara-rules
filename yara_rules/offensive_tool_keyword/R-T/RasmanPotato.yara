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
        $string1 = /\srasman\.exe/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string2 = /\/rasman\.exe/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string3 = "/RasmanPotato" nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string4 = /\[\!\]\sRasman\sservice\sis\snot\srunning\!/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string5 = /\[\+\]\sRasman\sservice\sis\serror/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string6 = /\[\+\]\sRasman\sservice\sis\srunning\!/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string7 = /\\RasMan\.cpp/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string8 = /\\rasman\.exe/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string9 = /\\RasMan\.sln/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string10 = /\\RasmanPotato/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string11 = "5AC309CE-1223-4FF5-AF84-24BCD0B9E4DC" nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string12 = /anypotato\.exe/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string13 = /Choose\sThe\sRPC\sFunction\s\[1\]VpnProtEngWinRtConnect\s\[2\]VpnProtEngGetInterface/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string14 = "dae7d1a42b0bb178bff2ca9729c31d59db045cd65db817cc9eca7a1721bc4c57" nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string15 = "magicRasMan" nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string16 = "Provided that the current user has the SeImpersonate privilege, this tool will have an escalation to SYSTEM" nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string17 = /rasman.{0,1000}whoami/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string18 = /RasMan\.vcxproj/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string19 = /rasman_c\.c/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string20 = /rasman_h\.h/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string21 = "RasmanPotato-master" nocase ascii wide

    condition:
        any of them
}
