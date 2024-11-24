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
        $string1 = " -a bruteforce " nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string2 = " --attack bruteforce" nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string3 = " --attack injection" nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string4 = " --attack vulns " nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string5 = /\ssitadel\.py/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string6 = /\/Sitadel\.git/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string7 = /\/sitadel\.log/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string8 = /\/sitadel\.py/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string9 = /\\sitadel\.log/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string10 = "docker run sitadel" nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string11 = "python3 sitadel" nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string12 = "sitadel http://" nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string13 = "sitadel https://" nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string14 = /sitadel\.py\s/ nocase ascii wide
        // Description: Web Application Security Scanner
        // Reference: https://github.com/shenril/Sitadel
        $string15 = /Sitadel\-master\.zip/ nocase ascii wide

    condition:
        any of them
}
