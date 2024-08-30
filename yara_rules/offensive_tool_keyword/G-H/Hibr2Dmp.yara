rule Hibr2Dmp
{
    meta:
        description = "Detection patterns for the tool 'Hibr2Dmp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hibr2Dmp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Convert hiberfil.sys to a dump file with hibr2dmp (can be used with windbg to exploit lsass dump)
        // Reference: https://github.com/mthcht/Purpleteam/blob/main/Simulation/Windows/System/dump_lsass_by_converting_hiberfil_to_dmp.ps1
        $string1 = /Hibr2Dmp\.exe/ nocase ascii wide

    condition:
        any of them
}
