rule Blackout
{
    meta:
        description = "Detection patterns for the tool 'Blackout' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Blackout"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string1 = /.{0,1000}\sBlackout\.cpp.{0,1000}/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string2 = /.{0,1000}\sBlackout\.sln.{0,1000}/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string3 = /.{0,1000}\sBlackout\.sys.{0,1000}/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string4 = /.{0,1000}\/Blackout\.cpp.{0,1000}/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string5 = /.{0,1000}\/Blackout\.exe.{0,1000}/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string6 = /.{0,1000}\/Blackout\.git.{0,1000}/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string7 = /.{0,1000}\/Blackout\.sln.{0,1000}/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string8 = /.{0,1000}\/Blackout\.sys.{0,1000}/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string9 = /.{0,1000}\\Blackout\.cpp.{0,1000}/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string10 = /.{0,1000}\\Blackout\.exe.{0,1000}/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string11 = /.{0,1000}\\Blackout\.sln.{0,1000}/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string12 = /.{0,1000}\\Blackout\.sys.{0,1000}/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string13 = /.{0,1000}\\Blackout\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string14 = /.{0,1000}Blackout\.exe\s.{0,1000}/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string15 = /.{0,1000}ZeroMemoryEx\/Blackout.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
