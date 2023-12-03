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
        $string1 = /.{0,1000}\/DebugAmsi\.git.{0,1000}/ nocase ascii wide
        // Description: DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // Reference: https://github.com/MzHmO/DebugAmsi
        $string2 = /.{0,1000}375D8508\-F60D\-4E24\-9DF6\-1E591D2FA474.{0,1000}/ nocase ascii wide
        // Description: DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // Reference: https://github.com/MzHmO/DebugAmsi
        $string3 = /.{0,1000}DebugAmsi\.exe.{0,1000}/ nocase ascii wide
        // Description: DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // Reference: https://github.com/MzHmO/DebugAmsi
        $string4 = /.{0,1000}DebugAmsi\.sln.{0,1000}/ nocase ascii wide
        // Description: DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // Reference: https://github.com/MzHmO/DebugAmsi
        $string5 = /.{0,1000}DebugAmsi\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // Reference: https://github.com/MzHmO/DebugAmsi
        $string6 = /.{0,1000}DebugAmsi\-main.{0,1000}/ nocase ascii wide
        // Description: DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // Reference: https://github.com/MzHmO/DebugAmsi
        $string7 = /.{0,1000}DebugAmsix64\.exe.{0,1000}/ nocase ascii wide
        // Description: DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // Reference: https://github.com/MzHmO/DebugAmsi
        $string8 = /.{0,1000}DebugAmsix86\.exe.{0,1000}/ nocase ascii wide
        // Description: DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // Reference: https://github.com/MzHmO/DebugAmsi
        $string9 = /.{0,1000}MzHmO\/DebugAmsi.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
