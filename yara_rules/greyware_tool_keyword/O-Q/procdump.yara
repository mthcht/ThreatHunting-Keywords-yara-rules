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
        $string1 = /procdump.{0,1000}lsass/ nocase ascii wide
        // Description: dump lsass process with procdump
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string2 = /procdump.{0,1000}lsass/ nocase ascii wide
        // Description: full dump with procdump (often used to dump lsass)
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string3 = /procdump\.exe.{0,1000}\s\-ma/ nocase ascii wide
        // Description: dump lsass process with procdump
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string4 = /procdump64.{0,1000}lsass/ nocase ascii wide

    condition:
        any of them
}
