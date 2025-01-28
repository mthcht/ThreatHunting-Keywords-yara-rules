rule Procdump
{
    meta:
        description = "Detection patterns for the tool 'Procdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Procdump"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: dump lsass process with procdump
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string1 = /\s\-ma\slssas\.exe/ nocase ascii wide
        // Description: dump lsass process with procdump
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string2 = /\/Procdump\.zip/ nocase ascii wide
        // Description: dump lsass process with procdump
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string3 = /\\lsass\.dmp/ nocase ascii wide
        // Description: dump lsass process with procdump
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string4 = /\\Procdump\.zip/ nocase ascii wide
        // Description: dump lsass process with procdump
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string5 = /\\SOFTWARE\\Sysinternals\\ProcDump\\/ nocase ascii wide
        // Description: Dump files might contain sensitive data and are often created as part of debugging processes or by attackers exfiltrating data. Users\Public should not be used
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string6 = /\\Users\\Public\\.{0,1000}\.dmp/ nocase ascii wide
        // Description: dump lsass process with procdump
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string7 = /\<Data\sName\=\'PipeName\'\>\\lsass\<\/Data\>\<Data\sName\=\'Image\'\>.{0,1000}procdump.{0,1000}\<\/Data\>/ nocase ascii wide
        // Description: dump lsass process with procdump
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string8 = ">ProcDump<" nocase ascii wide
        // Description: dump lsass process with procdump
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string9 = /procdump.{0,1000}lsass/ nocase ascii wide
        // Description: dump lsass process with procdump
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string10 = /procdump.{0,1000}lsass/ nocase ascii wide
        // Description: full dump with procdump (often used to dump lsass)
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string11 = /procdump\.exe.{0,1000}\s\-ma/ nocase ascii wide
        // Description: dump lsass process with procdump
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string12 = /procdump64.{0,1000}lsass/ nocase ascii wide
        // Description: usage of procdump (often used to dump lsass)
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string13 = /procdump64\.exe/ nocase ascii wide

    condition:
        any of them
}
