rule DumpLSASS
{
    meta:
        description = "Detection patterns for the tool 'DumpLSASS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpLSASS"
        rule_category = "signature_keyword"

    strings:
        // Description: Lsass dumping tool - 50 ways of dumping lsass
        // Reference: https://github.com/elementalsouls/DumpLSASS
        $string1 = "ATK/MultiDump-" nocase ascii wide
        // Description: Lsass dumping tool - 50 ways of dumping lsass
        // Reference: https://github.com/elementalsouls/DumpLSASS
        $string2 = /HackTool\.LsassDumper/ nocase ascii wide

    condition:
        any of them
}
