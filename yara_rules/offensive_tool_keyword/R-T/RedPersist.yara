rule RedPersist
{
    meta:
        description = "Detection patterns for the tool 'RedPersist' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RedPersist"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string1 = /.{0,1000}\.exe\s\-\-eventviewer\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string2 = /.{0,1000}\.exe\s\-\-pwsh\s.{0,1000}\.ps1\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string3 = /.{0,1000}\.exe\s\-\-schedule\s.{0,1000}\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string4 = /.{0,1000}\.exe\s\-\-screensaver\s.{0,1000}:\\.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string5 = /.{0,1000}\.exe\s\-\-startup\s.{0,1000}:\\.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string6 = /.{0,1000}\.exe\s\-\-winlogon\s.{0,1000}\s.{0,1000}:\\.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string7 = /.{0,1000}\.exe\s\-\-wmi\s.{0,1000}:\\.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string8 = /.{0,1000}\/RedPersist\.exe.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string9 = /.{0,1000}\/RedPersist\.git.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string10 = /.{0,1000}\\RedPersist\.exe.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string11 = /.{0,1000}\\RedPersist\.pdb.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string12 = /.{0,1000}\\RedPersist\.sln.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string13 = /.{0,1000}\\RedPersist\-main\\.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string14 = /.{0,1000}\]\sEventviewer\sPersistence\screated.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string15 = /.{0,1000}\]\sExtension\sHijacking\sPersistence\screated.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string16 = /.{0,1000}\]\sPowershell\sPersistence\screated.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string17 = /.{0,1000}\]\sScreensaver\sPersistence\screated.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string18 = /.{0,1000}\]\sStartup\sPersistence\screated.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string19 = /.{0,1000}\]\sUserInitMprLogonScript\sPersistence\screated.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string20 = /.{0,1000}BD745A5E\-A1E9\-4FDD\-A15B\-E9F303A625AE.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string21 = /.{0,1000}bd745a5e\-a1e9\-4fdd\-a15b\-e9f303a625ae.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string22 = /.{0,1000}Hello\sFrom\ssadsad\sTeam.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string23 = /.{0,1000}mertdas\/RedPersist.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string24 = /.{0,1000}namespace\sRedPersist\.Persist.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string25 = /.{0,1000}Persist\\autorun\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string26 = /.{0,1000}Persist\\eventviewer\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string27 = /.{0,1000}Persist\\powershell\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string28 = /.{0,1000}Persist\\screensaver\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string29 = /.{0,1000}Persist\\startup\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string30 = /.{0,1000}Persist\\winlogon\.cs.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
