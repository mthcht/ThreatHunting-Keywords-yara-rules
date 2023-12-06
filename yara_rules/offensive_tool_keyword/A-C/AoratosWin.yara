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
        $string1 = /\/AoratosWin\// nocase ascii wide
        // Description: A tool that removes traces of executed applications on Windows OS.
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string2 = /\\AoratosWin/ nocase ascii wide
        // Description: AoratosWin A tool that removes traces of executed applications on Windows OS
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string3 = /AoratosWin.{0,1000}\.zip/ nocase ascii wide
        // Description: AoratosWin A tool that removes traces of executed applications on Windows OS
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string4 = /AoratosWin\.csproj/ nocase ascii wide
        // Description: A tool that removes traces of executed applications on Windows OS.
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string5 = /AoratosWin\.exe/ nocase ascii wide
        // Description: AoratosWin A tool that removes traces of executed applications on Windows OS
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string6 = /AoratosWin\.exe/ nocase ascii wide
        // Description: AoratosWin A tool that removes traces of executed applications on Windows OS
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string7 = /AoratosWin\.git/ nocase ascii wide
        // Description: AoratosWin A tool that removes traces of executed applications on Windows OS
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string8 = /AoratosWin\.sln/ nocase ascii wide
        // Description: A tool that removes traces of executed applications on Windows OS.
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string9 = /AoratosWin_.{0,1000}\.zip/ nocase ascii wide
        // Description: A tool that removes traces of executed applications on Windows OS.
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string10 = /PinoyWH1Z\/AoratosWin/ nocase ascii wide
        // Description: AoratosWin A tool that removes traces of executed applications on Windows OS
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string11 = /PinoyWH1Z\/AoratosWin/ nocase ascii wide
        // Description: A tool that removes traces of executed applications on Windows OS.
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string12 = /removeRegTrace/ nocase ascii wide
        // Description: A tool that removes traces of executed applications on Windows OS.
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string13 = /whoami\s\/user/ nocase ascii wide

    condition:
        any of them
}
