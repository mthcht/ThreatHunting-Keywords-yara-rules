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
        $string1 = /icacls\s\\"C\:\\windows\\system32\\config\\SAM\\"\s\/grant/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string2 = /icacls\s.{0,100}\(x86\)\\360\\"\s.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string3 = /icacls\s.{0,100}\\360safe.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string4 = /icacls\s.{0,100}\\AVAST\sSoftware.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string5 = /icacls\s.{0,100}\\AVG\\".{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string6 = /icacls\s.{0,100}\\Avira.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string7 = /icacls\s.{0,100}\\Cezurity.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string8 = /icacls\s.{0,100}\\COMODO.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string9 = /icacls\s.{0,100}\\Doctor\sWeb.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string10 = /icacls\s.{0,100}\\Enigma\sSoftware\sGroup.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string11 = /icacls\s.{0,100}\\ESET.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string12 = /icacls\s.{0,100}\\GRIZZLY\sAntivirus.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string13 = /icacls\s.{0,100}\\grizzly.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string14 = /icacls\s.{0,100}\\Kaspersky\sLab.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string15 = /icacls\s.{0,100}\\Malwarebytes.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string16 = /icacls\s.{0,100}\\Malwarebytes.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string17 = /icacls\s.{0,100}\\McAfee.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string18 = /icacls\s.{0,100}\\Norton.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string19 = /icacls\s.{0,100}\\Panda\sSecurity.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string20 = /icacls\s.{0,100}\\SpyHunter.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: malware behavior - modify the permissions on files or directories that match AV name
        // Reference: https://www.hybrid-analysis.com/sample/22a2fc907d960e67fe9def8946907fd324f77afce3f2792750f1ddb1de76fc9f/5ed63f715448965c0d232702
        $string21 = /icacls\s.{0,100}\\SpyHunter.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
        // Description: automated sticky keys backdoor + credentials harvesting
        // Reference: https://github.com/l3m0n/WinPirate
        $string22 = /icacls\sc\:\\windows\\system32\\sethc\.exe\s/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://www.pavel.gr/blog/neutralising-amsi-system-wide-as-an-admin
        $string23 = /icacls\.exe\sC\:\\Windows\\System32\\amsi\.dll\s\/grant\sadministrators\:F/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
