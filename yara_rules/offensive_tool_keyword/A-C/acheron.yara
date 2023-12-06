rule acheron
{
    meta:
        description = "Detection patterns for the tool 'acheron' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "acheron"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: indirect syscalls for AV/EDR evasion in Go assembly
        // Reference: https://github.com/f1zm0/acheron
        $string1 = /\/acheron\.git/ nocase ascii wide
        // Description: indirect syscalls for AV/EDR evasion in Go assembly
        // Reference: https://github.com/f1zm0/acheron
        $string2 = /\/acheron\.go/ nocase ascii wide
        // Description: indirect syscalls for AV/EDR evasion in Go assembly
        // Reference: https://github.com/f1zm0/acheron
        $string3 = /\/direct_syscall_amd64\.s/ nocase ascii wide
        // Description: indirect syscalls for AV/EDR evasion in Go assembly
        // Reference: https://github.com/f1zm0/acheron
        $string4 = /\/sc_inject\/inject\// nocase ascii wide
        // Description: indirect syscalls for AV/EDR evasion in Go assembly
        // Reference: https://github.com/f1zm0/acheron
        $string5 = /acheron\-master\.zip/ nocase ascii wide
        // Description: indirect syscalls for AV/EDR evasion in Go assembly
        // Reference: https://github.com/f1zm0/acheron
        $string6 = /f1zm0\/acheron/ nocase ascii wide
        // Description: indirect syscalls for AV/EDR evasion in Go assembly
        // Reference: https://github.com/f1zm0/acheron
        $string7 = /process_snapshot\.exe/ nocase ascii wide
        // Description: indirect syscalls for AV/EDR evasion in Go assembly
        // Reference: https://github.com/f1zm0/acheron
        $string8 = /sc_inject_direct\.exe/ nocase ascii wide
        // Description: indirect syscalls for AV/EDR evasion in Go assembly
        // Reference: https://github.com/f1zm0/acheron
        $string9 = /sc_inject_indirect\.exe/ nocase ascii wide

    condition:
        any of them
}
