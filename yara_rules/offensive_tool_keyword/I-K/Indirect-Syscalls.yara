rule Indirect_Syscalls
{
    meta:
        description = "Detection patterns for the tool 'Indirect-Syscalls' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Indirect-Syscalls"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Indirect syscalls serve as an evolution of direct syscalls and enable enhanced EDR evasion by legitimizing syscall command execution and return statement within the ntdll.dll memory. This stealthy operation partially implements the syscall stub in the Indirect Syscall assembly itself.
        // Reference: https://github.com/VirtualAlllocEx/Direct-Syscalls-vs-Indirect-Syscalls
        $string1 = /CT_Indirect_Syscalls\.c/ nocase ascii wide
        // Description: Indirect syscalls serve as an evolution of direct syscalls and enable enhanced EDR evasion by legitimizing syscall command execution and return statement within the ntdll.dll memory. This stealthy operation partially implements the syscall stub in the Indirect Syscall assembly itself.
        // Reference: https://github.com/VirtualAlllocEx/Direct-Syscalls-vs-Indirect-Syscalls
        $string2 = /CT_Indirect_Syscalls\.exe/ nocase ascii wide
        // Description: Indirect syscalls serve as an evolution of direct syscalls and enable enhanced EDR evasion by legitimizing syscall command execution and return statement within the ntdll.dll memory. This stealthy operation partially implements the syscall stub in the Indirect Syscall assembly itself.
        // Reference: https://github.com/VirtualAlllocEx/Direct-Syscalls-vs-Indirect-Syscalls
        $string3 = /CT_Indirect_Syscalls\.sln/ nocase ascii wide
        // Description: Indirect syscalls serve as an evolution of direct syscalls and enable enhanced EDR evasion by legitimizing syscall command execution and return statement within the ntdll.dll memory. This stealthy operation partially implements the syscall stub in the Indirect Syscall assembly itself.
        // Reference: https://github.com/VirtualAlllocEx/Direct-Syscalls-vs-Indirect-Syscalls
        $string4 = /CT_Indirect_Syscalls\.vcxproj/ nocase ascii wide
        // Description: Indirect syscalls serve as an evolution of direct syscalls and enable enhanced EDR evasion by legitimizing syscall command execution and return statement within the ntdll.dll memory. This stealthy operation partially implements the syscall stub in the Indirect Syscall assembly itself.
        // Reference: https://github.com/VirtualAlllocEx/Direct-Syscalls-vs-Indirect-Syscalls
        $string5 = /Direct\-Syscalls\-vs\-Indirect\-Syscalls\.git/ nocase ascii wide

    condition:
        any of them
}
