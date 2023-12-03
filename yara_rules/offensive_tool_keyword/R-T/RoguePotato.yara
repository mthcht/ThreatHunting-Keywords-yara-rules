rule RoguePotato
{
    meta:
        description = "Detection patterns for the tool 'RoguePotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RoguePotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/RoguePotato
        $string1 = /.{0,1000}\/RoguePotato\.git.{0,1000}/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/RoguePotato
        $string2 = /.{0,1000}105C2C6D\-1C0A\-4535\-A231\-80E355EFB112.{0,1000}/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/RoguePotato
        $string3 = /.{0,1000}61CE6716\-E619\-483C\-B535\-8694F7617548.{0,1000}/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/RoguePotato
        $string4 = /.{0,1000}antonioCoco\/RoguePotato.{0,1000}/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/RoguePotato
        $string5 = /.{0,1000}RogueOxidResolver\.cpp.{0,1000}/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/RoguePotato
        $string6 = /.{0,1000}RoguePotato\.cpp.{0,1000}/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/RoguePotato
        $string7 = /.{0,1000}RoguePotato\.exe.{0,1000}/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/RoguePotato
        $string8 = /.{0,1000}RoguePotato\.sln.{0,1000}/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/RoguePotato
        $string9 = /.{0,1000}RoguePotato\.zip.{0,1000}/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/RoguePotato
        $string10 = /.{0,1000}RoguePotato\-master.{0,1000}/ nocase ascii wide
        // Description: Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/RoguePotato
        $string11 = /.{0,1000}TokenKidnapping\.cpp.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
