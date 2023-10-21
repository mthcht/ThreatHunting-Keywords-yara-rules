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
        $string1 = /dllexploit\./ nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string2 = /lsass\.exe.*\.dmp/ nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string3 = /PPLdump/ nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string4 = /PPLdump\.exe/ nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string5 = /PPLdump64\.exe/ nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string6 = /PPLdumpDll/ nocase ascii wide

    condition:
        any of them
}