rule Quasar
{
    meta:
        description = "Detection patterns for the tool 'Quasar' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Quasar"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string1 = /\sCN\=Quasar\sServer\sCA/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string2 = /\/Quasar\.git/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string3 = /\/Quasar\.v.{0,1000}\.zip/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string4 = /\/Quasar\/releases/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string5 = /\\appdata\\roaming\\.{0,1000}\'DestPort\'\>4782\<\/Data\>/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string6 = /\\CurrentVersion\\Run\\Quasar\sClient\sStartup/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string7 = /\\Prefetch\\QUASAR\.EXE/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string8 = /\\Program\sFiles\\SubDir\\Client\.exe/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string9 = /\\Quasar\.Client\\/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string10 = /\\Quasar\.Common\\.{0,1000}\.cs/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string11 = /\\quasar\.p12/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string12 = /\\Quasar\.v.{0,1000}\.zip/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string13 = /\\Quasar\-master/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string14 = /\\Users\\mthcht\\AppData\\Roaming\\SubDir\\Client\.exe/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string15 = /\\Windows\\system32\\SubDir\\Client\.exe/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string16 = /14CA405B\-8BAC\-48AB\-9FBA\-8FB5DF88FD0D/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string17 = /32A2A734\-7429\-47E6\-A362\-E344A19C0D85/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string18 = /9F5CF56A\-DDB2\-4F40\-AB99\-2A1DC47588E1/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string19 = /Backdoor\.Quasar/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string20 = /C7C363BA\-E5B6\-4E18\-9224\-39BC8DA73172/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string21 = /CFCD0759E20F29C399C9D4210BE614E4E020BEE8/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string22 = /localhost\:4782/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string23 = /namespace\sQuasar\.Client/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string24 = /namespace\sQuasar\.Server/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string25 = /ping\s\-n\s10\slocalhost\s\>\snul/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string26 = /Quasar\sClient\sStartup/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string27 = /Quasar\sv.{0,1000}\\Client\-built\.exe/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string28 = /Quasar\.Client\./ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string29 = /Quasar\.Common\.Tests\\/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string30 = /Quasar\.exe/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string31 = /Quasar\.Server/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string32 = /Quasar\.Server\\Program\.cs/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string33 = /Quasar\.sln/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string34 = /Quasar\.v1\.4\.1\.zip/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string35 = /quasar\/Quasar/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string36 = /Quasar\-master\.zip/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string37 = /QuasarRAT/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // Reference: https://github.com/quasar/Quasar
        $string38 = /ylAo2kAlUS2kYkala\!/ nocase ascii wide

    condition:
        any of them
}
