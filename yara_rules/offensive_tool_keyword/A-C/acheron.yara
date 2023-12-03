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
        $string1 = /.{0,1000}\/acheron\.git.{0,1000}/ nocase ascii wide
        // Description: indirect syscalls for AV/EDR evasion in Go assembly
        // Reference: https://github.com/f1zm0/acheron
        $string2 = /.{0,1000}\/acheron\.go.{0,1000}/ nocase ascii wide
        // Description: indirect syscalls for AV/EDR evasion in Go assembly
        // Reference: https://github.com/f1zm0/acheron
        $string3 = /.{0,1000}\/direct_syscall_amd64\.s.{0,1000}/ nocase ascii wide
        // Description: indirect syscalls for AV/EDR evasion in Go assembly
        // Reference: https://github.com/f1zm0/acheron
        $string4 = /.{0,1000}\/sc_inject\/inject\/.{0,1000}/ nocase ascii wide
        // Description: indirect syscalls for AV/EDR evasion in Go assembly
        // Reference: https://github.com/f1zm0/acheron
        $string5 = /.{0,1000}acheron\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: indirect syscalls for AV/EDR evasion in Go assembly
        // Reference: https://github.com/f1zm0/acheron
        $string6 = /.{0,1000}f1zm0\/acheron.{0,1000}/ nocase ascii wide
        // Description: indirect syscalls for AV/EDR evasion in Go assembly
        // Reference: https://github.com/f1zm0/acheron
        $string7 = /.{0,1000}process_snapshot\.exe.{0,1000}/ nocase ascii wide
        // Description: indirect syscalls for AV/EDR evasion in Go assembly
        // Reference: https://github.com/f1zm0/acheron
        $string8 = /.{0,1000}sc_inject_direct\.exe.{0,1000}/ nocase ascii wide
        // Description: indirect syscalls for AV/EDR evasion in Go assembly
        // Reference: https://github.com/f1zm0/acheron
        $string9 = /.{0,1000}sc_inject_indirect\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
