rule AoratosWin
{
    meta:
        description = "Detection patterns for the tool 'AoratosWin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AoratosWin"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool that removes traces of executed applications on Windows OS.
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string1 = "/AoratosWin/" nocase ascii wide
        // Description: A tool that removes traces of executed applications on Windows OS.
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string2 = /\\AoratosWin/ nocase ascii wide
        // Description: AoratosWin A tool that removes traces of executed applications on Windows OS
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string3 = /AoratosWin.{0,1000}\.zip/ nocase ascii wide
        // Description: AoratosWin A tool that removes traces of executed applications on Windows OS
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string4 = /AoratosWin\.csproj/ nocase ascii wide
        // Description: AoratosWin A tool that removes traces of executed applications on Windows OS
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string5 = /AoratosWin\.exe/ nocase ascii wide
        // Description: AoratosWin A tool that removes traces of executed applications on Windows OS
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string6 = /AoratosWin\.git/ nocase ascii wide
        // Description: AoratosWin A tool that removes traces of executed applications on Windows OS
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string7 = /AoratosWin\.sln/ nocase ascii wide
        // Description: A tool that removes traces of executed applications on Windows OS.
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string8 = /AoratosWin_.{0,1000}\.zip/ nocase ascii wide
        // Description: AoratosWin A tool that removes traces of executed applications on Windows OS
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string9 = "E731C71B-4D1B-4BE7-AA4D-EDA52AF7F256" nocase ascii wide
        // Description: A tool that removes traces of executed applications on Windows OS.
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string10 = "PinoyWH1Z/AoratosWin" nocase ascii wide
        // Description: A tool that removes traces of executed applications on Windows OS.
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string11 = "removeRegTrace" nocase ascii wide
        // Description: A tool that removes traces of executed applications on Windows OS.
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string12 = "whoami /user" nocase ascii wide

    condition:
        any of them
}
