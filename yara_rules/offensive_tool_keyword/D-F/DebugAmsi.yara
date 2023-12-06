rule DebugAmsi
{
    meta:
        description = "Detection patterns for the tool 'DebugAmsi' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DebugAmsi"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // Reference: https://github.com/MzHmO/DebugAmsi
        $string1 = /\/DebugAmsi\.git/ nocase ascii wide
        // Description: DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // Reference: https://github.com/MzHmO/DebugAmsi
        $string2 = /375D8508\-F60D\-4E24\-9DF6\-1E591D2FA474/ nocase ascii wide
        // Description: DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // Reference: https://github.com/MzHmO/DebugAmsi
        $string3 = /DebugAmsi\.exe/ nocase ascii wide
        // Description: DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // Reference: https://github.com/MzHmO/DebugAmsi
        $string4 = /DebugAmsi\.sln/ nocase ascii wide
        // Description: DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // Reference: https://github.com/MzHmO/DebugAmsi
        $string5 = /DebugAmsi\.vcxproj/ nocase ascii wide
        // Description: DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // Reference: https://github.com/MzHmO/DebugAmsi
        $string6 = /DebugAmsi\-main/ nocase ascii wide
        // Description: DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // Reference: https://github.com/MzHmO/DebugAmsi
        $string7 = /DebugAmsix64\.exe/ nocase ascii wide
        // Description: DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // Reference: https://github.com/MzHmO/DebugAmsi
        $string8 = /DebugAmsix86\.exe/ nocase ascii wide
        // Description: DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // Reference: https://github.com/MzHmO/DebugAmsi
        $string9 = /MzHmO\/DebugAmsi/ nocase ascii wide

    condition:
        any of them
}
