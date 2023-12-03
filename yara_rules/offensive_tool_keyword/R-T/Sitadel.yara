rule Sitadel
{
    meta:
        description = "Detection patterns for the tool 'Sitadel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sitadel"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string1 = /.{0,1000}\s\-a\sbruteforce\s.{0,1000}/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string2 = /.{0,1000}\s\-\-attack\sbruteforce.{0,1000}/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string3 = /.{0,1000}\s\-\-attack\sinjection.{0,1000}/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string4 = /.{0,1000}\s\-\-attack\svulns\s.{0,1000}/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string5 = /.{0,1000}\ssitadel\.py.{0,1000}/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string6 = /.{0,1000}\/Sitadel\.git.{0,1000}/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string7 = /.{0,1000}\/sitadel\.log.{0,1000}/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string8 = /.{0,1000}\/sitadel\.py.{0,1000}/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string9 = /.{0,1000}\\sitadel\.log.{0,1000}/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string10 = /.{0,1000}docker\srun\ssitadel.{0,1000}/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string11 = /.{0,1000}python3\ssitadel.{0,1000}/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string12 = /.{0,1000}sitadel\shttp:\/\/.{0,1000}/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string13 = /.{0,1000}sitadel\shttps:\/\/.{0,1000}/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string14 = /.{0,1000}sitadel\.py\s.{0,1000}/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string15 = /.{0,1000}Sitadel\-master\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
