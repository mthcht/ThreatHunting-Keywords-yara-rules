rule DumpLSASS
{
    meta:
        description = "Detection patterns for the tool 'DumpLSASS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpLSASS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Lsass dumping tool - 50 ways of dumping lsass
        // Reference: https://github.com/elementalsouls/DumpLSASS
        $string1 = /\/DumpLSASS\.git/ nocase ascii wide
        // Description: Lsass dumping tool - 50 ways of dumping lsass
        // Reference: https://github.com/elementalsouls/DumpLSASS
        $string2 = /\/MultiDump\.exe/ nocase ascii wide
        // Description: Lsass dumping tool - 50 ways of dumping lsass
        // Reference: https://github.com/elementalsouls/DumpLSASS
        $string3 = /\[\!\]\sDumping\sLSASS\sRequires\sElevated\sPriviledges\!/ nocase ascii wide
        // Description: Lsass dumping tool - 50 ways of dumping lsass
        // Reference: https://github.com/elementalsouls/DumpLSASS
        $string4 = /\[\!\]\sFailed\sto\sLocate\sLSASS\sDump\sFile\!/ nocase ascii wide
        // Description: Lsass dumping tool - 50 ways of dumping lsass
        // Reference: https://github.com/elementalsouls/DumpLSASS
        $string5 = /\[\+\]\sLSASS\sDump\sRead\:\s/ nocase ascii wide
        // Description: Lsass dumping tool - 50 ways of dumping lsass
        // Reference: https://github.com/elementalsouls/DumpLSASS
        $string6 = /\[i\]\sDumping\sLSASS\sUsing\s/ nocase ascii wide
        // Description: Lsass dumping tool - 50 ways of dumping lsass
        // Reference: https://github.com/elementalsouls/DumpLSASS
        $string7 = /\\a\\1\\s\\x64\\Release\\ProcDump64\.pdb/ nocase ascii wide
        // Description: Lsass dumping tool - 50 ways of dumping lsass
        // Reference: https://github.com/elementalsouls/DumpLSASS
        $string8 = /\\DumpLSASS\-main/ nocase ascii wide
        // Description: Lsass dumping tool - 50 ways of dumping lsass
        // Reference: https://github.com/elementalsouls/DumpLSASS
        $string9 = /\\MultiDump\.exe/ nocase ascii wide
        // Description: Lsass dumping tool - 50 ways of dumping lsass
        // Reference: https://github.com/elementalsouls/DumpLSASS
        $string10 = /\\Users\\Public\\lsass\.dmp/ nocase ascii wide
        // Description: Lsass dumping tool - 50 ways of dumping lsass
        // Reference: https://github.com/elementalsouls/DumpLSASS
        $string11 = /DumpLSASS\-main\.zip/ nocase ascii wide
        // Description: Lsass dumping tool - 50 ways of dumping lsass
        // Reference: https://github.com/elementalsouls/DumpLSASS
        $string12 = "elementalsouls/DumpLSASS" nocase ascii wide
        // Description: Lsass dumping tool - 50 ways of dumping lsass
        // Reference: https://github.com/elementalsouls/DumpLSASS
        $string13 = "f150333a3943f2c7398e0dd3f97a2cb3f1c1653a220785a977ba9a7ff692dab1" nocase ascii wide
        // Description: Lsass dumping tool - 50 ways of dumping lsass
        // Reference: https://github.com/elementalsouls/DumpLSASS
        $string14 = /Users\\\\Public\\\\lsass\.dmp/ nocase ascii wide

    condition:
        any of them
}
