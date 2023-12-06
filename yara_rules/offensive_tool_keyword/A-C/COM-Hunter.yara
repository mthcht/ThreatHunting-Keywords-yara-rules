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
        $string1 = /\sPersist\sGeneral\s.{0,1000}\.dll/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string2 = /\sPersist\sTasksch\s.{0,1000}\.dll/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string3 = /\sPersist\sTreatAs\s.{0,1000}\.dll/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string4 = /\.exe\sSearch\sFind\-Persist/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string5 = /\/COM\-Hunter\.csproj/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string6 = /\/COM\-Hunter\.exe/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string7 = /\/COM\-Hunter\.git/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string8 = /\/COM\-Hunter\.sln/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string9 = /\\COM\-Hunter\.csproj/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string10 = /\\COM\-Hunter\.exe/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string11 = /\\COM\-Hunter\.sln/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string12 = /09323E4D\-BE0F\-452A\-9CA8\-B07D2CFA9804/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string13 = /COM\-Hunter_v.{0,1000}\.zip/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string14 = /COM\-Hunter\-main/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string15 = /nickvourd\/COM\-Hunter/ nocase ascii wide

    condition:
        any of them
}
