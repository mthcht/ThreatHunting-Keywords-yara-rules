rule POSTDump
{
    meta:
        description = "Detection patterns for the tool 'POSTDump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "POSTDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string1 = /\.exe\s\-\-signature\s\-\-driver/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string2 = /\/PostDump\.exe/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string3 = /\/PostDump\.exe/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string4 = /\/POSTDump\.git/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string5 = /\/POSTDump\.git/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string6 = /\\lsass\.dmp/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string7 = /\\POSTDump\.csproj/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string8 = /\\PostDump\.exe/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string9 = /\\PostDump\.exe/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string10 = /\\POSTDump\.sln/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string11 = /\\POSTMiniDump\\/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string12 = /ASR_bypass_to_dump_LSASS\.cs/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string13 = /Done\!\sCheck\sfor\sexisting\slsass\.dmp\sfile\sinto\scurrent\sfolder/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string14 = /E54195F0\-060C\-4B24\-98F2\-AD9FB5351045/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string15 = /E54195F0\-060C\-4B24\-98F2\-AD9FB5351045/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string16 = /namespace\sPOSTDump/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string17 = /namespace\sPOSTMiniDump/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string18 = /PostDump\.exe\s/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string19 = /PostDump\.exe\s/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string20 = /POSTDump\\Postdump\.cs/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string21 = /POSTDump\\PROCEXP\.sys/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string22 = /POSTDump\-main/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string23 = /POSTDump\-main/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string24 = /POSTMiniDump\.Data/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string25 = /POSTMiniDump\.MiniDump/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string26 = /POSTMiniDump\.Utils/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string27 = /python3\sdump\-restore\.py/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string28 = /YOLOP0wn\/POSTDump/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string29 = /YOLOP0wn\/POSTDump/ nocase ascii wide

    condition:
        any of them
}
