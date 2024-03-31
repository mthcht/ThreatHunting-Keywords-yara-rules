rule ChromeKatz
{
    meta:
        description = "Detection patterns for the tool 'ChromeKatz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ChromeKatz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string1 = /\.exe\s\.\\chrome\.DMP/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string2 = /\.exe\s\.\\msedge\.DMP/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string3 = /\/ChromeKatz\.git/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string4 = /\\BOF\-Template\\x64\\/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string5 = /\\ChromeKatz\.sln/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string6 = /\\CookieKatz\.vcxproj/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string7 = /\\CookieKatz\-BOF\\/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string8 = /\\CookieKatzMinidump\\/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string9 = /0C81C7D4\-736A\-4876\-A36E\-15E5B2EF5117/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string10 = /17a1d963e1565ecff5794a685188f34adc40bc12b4f31aa32db53b6956369827/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string11 = /2611455f4d60bc80f43cb13f480c6bee70497fffea48ed5c0b7d67e7fce33a52/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string12 = /33ccc2fca462fcf743513e4f01ebe3b7302e0158a44b8dfa1f3e56b78b3ff0be/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string13 = /36a659bab7eec62733d13b9e7f8a6ae891cfaf7cd2ec36824bf41f7e6b706944/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string14 = /726888af98eaa956dd40e486f4fcb93d7e12880f9540d9f28aabda8f90035c1a/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string15 = /CB790E12\-603E\-4C7C\-9DC1\-14A50819AF8C/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string16 = /ChromeKatz\/Memory\.cpp/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string17 = /ChromeKatz\/Process\.cpp/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string18 = /ChromeKatz\\Memory\.cpp/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string19 = /ChromeKatz\\Process\.cpp/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string20 = /cookie\-katz\schrome\s/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string21 = /cookie\-katz\schrome\s/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string22 = /cookie\-katz\sedge\s/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string23 = /CookieKatz\sMinidump\sparser/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string24 = /CookieKatz\sMinidump\sparser/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string25 = /cookie\-katz\swebview\s/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string26 = /CookieKatz\.exe/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string27 = /CookieKatzBOF\.cpp/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string28 = /CookieKatzBOF\.x64/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string29 = /CookieKatzBOF\.zip/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string30 = /CookieKatzMinidump\.exe/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string31 = /Dump\scookies\sfrom\sChrome\sor\sEdge/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string32 = /FDF5A0F3\-73DA\-4A8B\-804F\-EDD499A176EF/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string33 = /Kittens\slove\scookies\stoo\!\s\>\:3/ nocase ascii wide
        // Description: Dump cookies directly from Chrome process memory
        // Reference: https://github.com/Meckazin/ChromeKatz
        $string34 = /Meckazin\/ChromeKatz/ nocase ascii wide

    condition:
        any of them
}
