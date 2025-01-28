rule DocPlz
{
    meta:
        description = "Detection patterns for the tool 'DocPlz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DocPlz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string1 = /\sComunicationC2\.cpp/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string2 = /\/ComunicationC2\.cpp/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string3 = /\/DocPlz\.git/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string4 = /\/DocsPLZ\.cpp/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string5 = /\/DocsPLZ\.exe/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string6 = /\/ServerC2\.cpp/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string7 = /\/ServerC2\.exe/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string8 = /\\ComunicationC2\.cpp/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string9 = /\\DocsPLZ\.cpp/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string10 = /\\DocsPLZ\.exe/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string11 = /\\Persistence\.exe/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string12 = /\\ServerC2\.cpp/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string13 = /\\ServerC2\.exe/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string14 = /\\ServerC2\\ServerC2\./ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string15 = "4C3B106C-8782-4374-9459-851749072123" nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string16 = "5E0812A9-C727-44F3-A2E3-8286CDC3ED4F" nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string17 = /DocPlz\-main\.zip/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string18 = /DocsPLZ\\DocsPLZ\./ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string19 = "TheD1rkMtr/DocPlz" nocase ascii wide

    condition:
        any of them
}
