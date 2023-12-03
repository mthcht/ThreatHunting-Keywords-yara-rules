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
        $string1 = /.{0,1000}dllexploit\..{0,1000}/ nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string2 = /.{0,1000}lsass\.exe.{0,1000}\.dmp.{0,1000}/ nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string3 = /.{0,1000}PPLdump.{0,1000}/ nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string4 = /.{0,1000}PPLdump\.exe.{0,1000}/ nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string5 = /.{0,1000}PPLdump64\.exe.{0,1000}/ nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string6 = /.{0,1000}PPLdumpDll.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
