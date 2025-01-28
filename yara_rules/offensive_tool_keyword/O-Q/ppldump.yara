rule ppldump
{
    meta:
        description = "Detection patterns for the tool 'ppldump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ppldump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string1 = "6E8D2C12-255B-403C-9EF3-8A097D374DB2" nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string2 = /dllexploit\./ nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string3 = "FCE81BDA-ACAC-4892-969E-0414E765593B" nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string4 = /lsass\.exe.{0,1000}\.dmp/ nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string5 = "PPLdump" nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string6 = /PPLdump\.exe/ nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string7 = /PPLdump64\.exe/ nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string8 = "PPLdumpDll" nocase ascii wide

    condition:
        any of them
}
