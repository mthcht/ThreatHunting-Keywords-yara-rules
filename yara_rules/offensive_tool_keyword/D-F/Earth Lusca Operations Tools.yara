rule Earth_Lusca_Operations_Tools
{
    meta:
        description = "Detection patterns for the tool 'Earth Lusca Operations Tools' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Earth Lusca Operations Tools"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string1 = /.{0,1000}\shackergu\s.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string2 = /.{0,1000}\.\/agscript\s.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string3 = /.{0,1000}\.\/teamserver\s.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string4 = /.{0,1000}\/m\s.{0,1000}\.lnk.{0,1000}\s\/c\s.{0,1000}cmd\s\/c\secho\sf\|xcopy\s\@file\s\%temp\%.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string5 = /.{0,1000}\\Doraemon.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string6 = /.{0,1000}\\macoffe\.pdb.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string7 = /.{0,1000}\\mem_dll\.pdb.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string8 = /.{0,1000}\\pwn\.exe.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string9 = /.{0,1000}\\while_dll_ms.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string10 = /.{0,1000}cscript\s.{0,1000}wmi\.vbs\s\-h.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string11 = /.{0,1000}findstr\.exe\sTvndrgaaa.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string12 = /.{0,1000}fodhelperbypass.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string13 = /.{0,1000}for\s\/f\s\%\%i\sin\s\(C:\\Windows\\IME\\ok\.txt\).{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string14 = /.{0,1000}for\s\/r\sc:\\windows\\system32\\\s\%i\sin\s\(.{0,1000}sht.{0,1000}\.exe\).{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string15 = /.{0,1000}frpc\.exe\s\-c\sfrpc\.in.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string16 = /.{0,1000}libxselinux\.old.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string17 = /.{0,1000}libxselinux\.so.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string18 = /.{0,1000}megacmd\s\-conf\s.{0,1000}\sput\s.{0,1000}mega:.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string19 = /.{0,1000}net\sstart\sSysUpdate.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string20 = /.{0,1000}powershell\s.{0,1000}Get\-EventLog\s\-LogName\ssecurity\s\-Newest\s500\s\|\swhere\s{\$_\.EventID\s\-eq\s4624}\s\|\sformat\-list\s\-property\s.{0,1000}\s\|\sfindstr.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string21 = /.{0,1000}powershell\sIEX\s\(New\-Object\sNet\.WebClient\)\.DownloadString\(.{0,1000}\)\s\sGet\-NetComputer\s\-FullData\s.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string22 = /.{0,1000}powershell\sIEX\s\(New\-Object\sNet\.WebClient\)\.DownloadString.{0,1000}\.ps1.{0,1000}Get\-NetComputer\s\-FullData.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string23 = /.{0,1000}PowerShellMafia.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string24 = /.{0,1000}PowerView\.ps1.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string25 = /.{0,1000}Rar\sa\s\-v3g\s\-k\s\-r\s\-s\s\-m3\s.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string26 = /.{0,1000}tas389\.ps1.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string27 = /.{0,1000}ts\.php.{0,1000}vi\.txt.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string28 = /.{0,1000}we\.exe\s\-s\srssocks\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string29 = /.{0,1000}wevtutil\sqe\ssecurity\s\/format:text\s\/q:.{0,1000}Event\[System\[\(EventID\=4624\)\].{0,1000}find\s.{0,1000}Source\sNetwork\sAddress.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf
        $string30 = /.{0,1000}xs\.exe\s\-connect\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
