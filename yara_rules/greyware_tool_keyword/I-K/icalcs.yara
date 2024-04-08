rule icalcs
{
    meta:
        description = "Detection patterns for the tool 'icalcs' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "icalcs"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string1 = /icacls\s\"C\:\\windows\\system32\\config\\SAM\"\s\/grant/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string2 = /icacls\s.{0,1000}\(x86\)\\360\"\s.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string3 = /icacls\s.{0,1000}\\360safe.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string4 = /icacls\s.{0,1000}\\AVAST\sSoftware.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string5 = /icacls\s.{0,1000}\\AVG\".{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string6 = /icacls\s.{0,1000}\\Avira.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string7 = /icacls\s.{0,1000}\\Cezurity.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string8 = /icacls\s.{0,1000}\\COMODO.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string9 = /icacls\s.{0,1000}\\Doctor\sWeb.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string10 = /icacls\s.{0,1000}\\Enigma\sSoftware\sGroup.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string11 = /icacls\s.{0,1000}\\ESET.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string12 = /icacls\s.{0,1000}\\GRIZZLY\sAntivirus.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string13 = /icacls\s.{0,1000}\\grizzly.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string14 = /icacls\s.{0,1000}\\Kaspersky\sLab.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string15 = /icacls\s.{0,1000}\\Malwarebytes.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string16 = /icacls\s.{0,1000}\\Malwarebytes.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string17 = /icacls\s.{0,1000}\\McAfee.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string18 = /icacls\s.{0,1000}\\Norton.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string19 = /icacls\s.{0,1000}\\Panda\sSecurity.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string20 = /icacls\s.{0,1000}\\SpyHunter.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string21 = /icacls\s.{0,1000}\\SpyHunter.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: automated sticky keys backdoor + credentials harvesting
        // Reference: https://github.com/l3m0n/WinPirate
        $string22 = /icacls\sc\:\\windows\\system32\\sethc\.exe\s/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://www.pavel.gr/blog/neutralising-amsi-system-wide-as-an-admin
        $string23 = /icacls\.exe\sC\:\\Windows\\System32\\amsi\.dll\s\/grant\sadministrators\:F/ nocase ascii wide

    condition:
        any of them
}
