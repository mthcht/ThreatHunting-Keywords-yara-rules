rule SysWhispers3
{
    meta:
        description = "Detection patterns for the tool 'SysWhispers3' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SysWhispers3"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SysWhispers on Steroids - AV/EDR evasion via direct system calls.
        // Reference: https://github.com/klezVirus/SysWhispers3
        $string1 = /\s\-\-functions\sNtProtectVirtualMemory.{0,1000}NtWriteVirtualMemory\s\-o\ssyscalls_mem/ nocase ascii wide
        // Description: SysWhispers on Steroids - AV/EDR evasion via direct system calls.
        // Reference: https://github.com/klezVirus/SysWhispers3
        $string2 = /\s\-\-preset\sall\s\-o\ssyscalls_all/ nocase ascii wide
        // Description: SysWhispers on Steroids - AV/EDR evasion via direct system calls.
        // Reference: https://github.com/klezVirus/SysWhispers3
        $string3 = /\s\-\-preset\scommon\s\-o\ssyscalls_common/ nocase ascii wide
        // Description: SysWhispers on Steroids - AV/EDR evasion via direct system calls.
        // Reference: https://github.com/klezVirus/SysWhispers3
        $string4 = /\/SysWhispers2/ nocase ascii wide
        // Description: SysWhispers on Steroids - AV/EDR evasion via direct system calls.
        // Reference: https://github.com/klezVirus/SysWhispers3
        $string5 = /\/SysWhispers3/ nocase ascii wide
        // Description: SysWhispers on Steroids - AV/EDR evasion via direct system calls.
        // Reference: https://github.com/klezVirus/SysWhispers3
        $string6 = /\/SysWhispers3\.git/ nocase ascii wide
        // Description: SysWhispers on Steroids - AV/EDR evasion via direct system calls.
        // Reference: https://github.com/klezVirus/SysWhispers3
        $string7 = /syswhispers\.py/ nocase ascii wide

    condition:
        any of them
}
