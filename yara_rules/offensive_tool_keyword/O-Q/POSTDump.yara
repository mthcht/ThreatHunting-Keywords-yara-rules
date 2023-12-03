rule POSTDump
{
    meta:
        description = "Detection patterns for the tool 'POSTDump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "POSTDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string1 = /.{0,1000}\/PostDump\.exe.{0,1000}/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string2 = /.{0,1000}\/POSTDump\.git.{0,1000}/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string3 = /.{0,1000}\\lsass\.dmp.{0,1000}/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string4 = /.{0,1000}\\PostDump\.exe.{0,1000}/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string5 = /.{0,1000}E54195F0\-060C\-4B24\-98F2\-AD9FB5351045.{0,1000}/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string6 = /.{0,1000}PostDump\.exe\s.{0,1000}/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string7 = /.{0,1000}POSTDump\-main.{0,1000}/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string8 = /.{0,1000}YOLOP0wn\/POSTDump.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
