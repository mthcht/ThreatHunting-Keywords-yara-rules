rule SharpExShell
{
    meta:
        description = "Detection patterns for the tool 'SharpExShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpExShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string1 = /\/SharpExcelDCom\.exe/ nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string2 = /\/SharpExShell\.exe/ nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string3 = /\/SharpExShell\.git/ nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string4 = /\\SharpExcelDCom\.exe/ nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string5 = /\\SharpExShell\.exe/ nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string6 = /\\SharpExShell\.sln/ nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string7 = "13C84182-2F5F-4EE8-A37A-4483E7E57154" nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string8 = "37618f36a162e667eb98cb36bc1568524f87efc7cc12ef6d0ea4ef2f225c799d" nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string9 = "4848f468fc1f6b5c933d83be4e9295cf6af8eb74b789fdf0a6f116c7444808b2" nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string10 = "a63bf8aa62471b0cb62919e6e387482895a8027d5f763aba5f76572a595d7a31" nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string11 = "grayhatkiller/SharpExShell" nocase ascii wide

    condition:
        any of them
}
