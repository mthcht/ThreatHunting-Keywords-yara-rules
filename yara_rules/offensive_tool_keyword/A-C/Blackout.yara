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
        $string1 = /\sBlackout\.cpp/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string2 = /\sBlackout\.sln/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string3 = /\sBlackout\.sys/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string4 = /\/Blackout\.cpp/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string5 = /\/Blackout\.exe/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string6 = /\/Blackout\.git/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string7 = /\/Blackout\.sln/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string8 = /\/Blackout\.sys/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string9 = /\\Blackout\.cpp/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string10 = /\\Blackout\.exe/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string11 = /\\Blackout\.sln/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string12 = /\\Blackout\.sys/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string13 = /\\Blackout\.vcxproj/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string14 = /Blackout\.exe\s/ nocase ascii wide
        // Description: kill anti-malware protected processes using BYOVD
        // Reference: https://github.com/ZeroMemoryEx/Blackout
        $string15 = /ZeroMemoryEx\/Blackout/ nocase ascii wide

    condition:
        any of them
}
