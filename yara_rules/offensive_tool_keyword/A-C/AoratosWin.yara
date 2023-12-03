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
        $string1 = /.{0,1000}\/AoratosWin\/.{0,1000}/ nocase ascii wide
        // Description: A tool that removes traces of executed applications on Windows OS.
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string2 = /.{0,1000}\\AoratosWin.{0,1000}/ nocase ascii wide
        // Description: AoratosWin A tool that removes traces of executed applications on Windows OS
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string3 = /.{0,1000}AoratosWin.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: AoratosWin A tool that removes traces of executed applications on Windows OS
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string4 = /.{0,1000}AoratosWin\.csproj.{0,1000}/ nocase ascii wide
        // Description: A tool that removes traces of executed applications on Windows OS.
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string5 = /.{0,1000}AoratosWin\.exe.{0,1000}/ nocase ascii wide
        // Description: AoratosWin A tool that removes traces of executed applications on Windows OS
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string6 = /.{0,1000}AoratosWin\.exe.{0,1000}/ nocase ascii wide
        // Description: AoratosWin A tool that removes traces of executed applications on Windows OS
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string7 = /.{0,1000}AoratosWin\.git.{0,1000}/ nocase ascii wide
        // Description: AoratosWin A tool that removes traces of executed applications on Windows OS
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string8 = /.{0,1000}AoratosWin\.sln.{0,1000}/ nocase ascii wide
        // Description: A tool that removes traces of executed applications on Windows OS.
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string9 = /.{0,1000}AoratosWin_.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: A tool that removes traces of executed applications on Windows OS.
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string10 = /.{0,1000}PinoyWH1Z\/AoratosWin.{0,1000}/ nocase ascii wide
        // Description: AoratosWin A tool that removes traces of executed applications on Windows OS
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string11 = /.{0,1000}PinoyWH1Z\/AoratosWin.{0,1000}/ nocase ascii wide
        // Description: A tool that removes traces of executed applications on Windows OS.
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string12 = /.{0,1000}removeRegTrace.{0,1000}/ nocase ascii wide
        // Description: A tool that removes traces of executed applications on Windows OS.
        // Reference: https://github.com/PinoyWH1Z/AoratosWin
        $string13 = /.{0,1000}whoami\s\/user.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
