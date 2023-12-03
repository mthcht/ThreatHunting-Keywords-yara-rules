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
        $string1 = /.{0,1000}\sComunicationC2\.cpp.{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string2 = /.{0,1000}\/ComunicationC2\.cpp.{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string3 = /.{0,1000}\/DocPlz\.git.{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string4 = /.{0,1000}\/DocsPLZ\.cpp.{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string5 = /.{0,1000}\/DocsPLZ\.exe.{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string6 = /.{0,1000}\/Persistence\.cpp.{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string7 = /.{0,1000}\/ServerC2\.cpp.{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string8 = /.{0,1000}\/ServerC2\.exe.{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string9 = /.{0,1000}\\ComunicationC2\.cpp.{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string10 = /.{0,1000}\\DocsPLZ\.cpp.{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string11 = /.{0,1000}\\DocsPLZ\.exe.{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string12 = /.{0,1000}\\Persistence\.cpp.{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string13 = /.{0,1000}\\Persistence\.exe.{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string14 = /.{0,1000}\\ServerC2\.cpp.{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string15 = /.{0,1000}\\ServerC2\.exe.{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string16 = /.{0,1000}\\ServerC2\\ServerC2\..{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string17 = /.{0,1000}4C3B106C\-8782\-4374\-9459\-851749072123.{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string18 = /.{0,1000}5E0812A9\-C727\-44F3\-A2E3\-8286CDC3ED4F.{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string19 = /.{0,1000}DocPlz\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string20 = /.{0,1000}DocsPLZ\\DocsPLZ\..{0,1000}/ nocase ascii wide
        // Description: Documents Exfiltration and C2 project
        // Reference: https://github.com/TheD1rkMtr/DocPlz
        $string21 = /.{0,1000}TheD1rkMtr\/DocPlz.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
