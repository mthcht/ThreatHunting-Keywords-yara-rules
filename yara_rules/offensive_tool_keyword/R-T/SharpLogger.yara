rule SharpLogger
{
    meta:
        description = "Detection patterns for the tool 'SharpLogger' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpLogger"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Keylogger written in C#
        // Reference: https://github.com/djhohnstein/SharpLogger
        $string1 = /\/SharpLogger\.exe/ nocase ascii wide
        // Description: Keylogger written in C#
        // Reference: https://github.com/djhohnstein/SharpLogger
        $string2 = /\\SharpLogger\.exe/ nocase ascii wide
        // Description: Keylogger written in C#
        // Reference: https://github.com/djhohnstein/SharpLogger
        $string3 = /36E00152\-E073\-4DA8\-AA0C\-375B6DD680C4/ nocase ascii wide
        // Description: Keylogger written in C#
        // Reference: https://github.com/djhohnstein/SharpLogger
        $string4 = /4dbd32931bc77778850c20282a9e3adebd4d23b7ef4b0635380b520c432b48d9/ nocase ascii wide
        // Description: Keylogger written in C#
        // Reference: https://github.com/djhohnstein/SharpLogger
        $string5 = /9d7bfb3aeba4145896ece197216c4269deee6cce93eed3ffafe442ed05aeb4c4/ nocase ascii wide
        // Description: Keylogger written in C#
        // Reference: https://github.com/djhohnstein/SharpLogger
        $string6 = /djhohnstein\/SharpLogger/ nocase ascii wide
        // Description: Keylogger written in C#
        // Reference: https://github.com/djhohnstein/SharpLogger
        $string7 = /Keylogger\.csproj/ nocase ascii wide
        // Description: Keylogger written in C#
        // Reference: https://github.com/djhohnstein/SharpLogger
        $string8 = /Keylogger\.exe/ nocase ascii wide
        // Description: Keylogger written in C#
        // Reference: https://github.com/djhohnstein/SharpLogger
        $string9 = /namespace\sKeylogger/ nocase ascii wide

    condition:
        any of them
}
