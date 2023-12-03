rule COM_Hunter
{
    meta:
        description = "Detection patterns for the tool 'COM-Hunter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "COM-Hunter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string1 = /.{0,1000}\sPersist\sGeneral\s.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string2 = /.{0,1000}\sPersist\sTasksch\s.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string3 = /.{0,1000}\sPersist\sTreatAs\s.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string4 = /.{0,1000}\.exe\sSearch\sFind\-Persist.{0,1000}/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string5 = /.{0,1000}\/COM\-Hunter\.csproj.{0,1000}/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string6 = /.{0,1000}\/COM\-Hunter\.exe.{0,1000}/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string7 = /.{0,1000}\/COM\-Hunter\.git.{0,1000}/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string8 = /.{0,1000}\/COM\-Hunter\.sln.{0,1000}/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string9 = /.{0,1000}\\COM\-Hunter\.csproj.{0,1000}/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string10 = /.{0,1000}\\COM\-Hunter\.exe.{0,1000}/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string11 = /.{0,1000}\\COM\-Hunter\.sln.{0,1000}/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string12 = /.{0,1000}09323E4D\-BE0F\-452A\-9CA8\-B07D2CFA9804.{0,1000}/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string13 = /.{0,1000}COM\-Hunter_v.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string14 = /.{0,1000}COM\-Hunter\-main.{0,1000}/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string15 = /.{0,1000}nickvourd\/COM\-Hunter.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
