rule Direct_Syscalls
{
    meta:
        description = "Detection patterns for the tool 'Direct-Syscalls' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Direct-Syscalls"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Direct-Syscalls technique is a method employed by malware to hide its malicious behavior and avoid detection. This technique involves executing system calls directly thus bypassing the Windows API (Application Programming Interface) which is typically monitored by EDRs
        // Reference: https://github.com/VirtualAlllocEx/Direct-Syscalls-vs-Indirect-Syscalls
        $string1 = /Direct_Syscalls_Create_Thread\.c/ nocase ascii wide
        // Description: Direct-Syscalls technique is a method employed by malware to hide its malicious behavior and avoid detection. This technique involves executing system calls directly thus bypassing the Windows API (Application Programming Interface) which is typically monitored by EDRs
        // Reference: https://github.com/VirtualAlllocEx/Direct-Syscalls-vs-Indirect-Syscalls
        $string2 = /Direct_Syscalls_Create_Thread\.exe/ nocase ascii wide
        // Description: Direct-Syscalls technique is a method employed by malware to hide its malicious behavior and avoid detection. This technique involves executing system calls directly thus bypassing the Windows API (Application Programming Interface) which is typically monitored by EDRs
        // Reference: https://github.com/VirtualAlllocEx/Direct-Syscalls-vs-Indirect-Syscalls
        $string3 = /Direct_Syscalls_Create_Thread\.sln/ nocase ascii wide
        // Description: Direct-Syscalls technique is a method employed by malware to hide its malicious behavior and avoid detection. This technique involves executing system calls directly thus bypassing the Windows API (Application Programming Interface) which is typically monitored by EDRs
        // Reference: https://github.com/VirtualAlllocEx/Direct-Syscalls-vs-Indirect-Syscalls
        $string4 = /Direct_Syscalls_Create_Thread\.vcxproj/ nocase ascii wide

    condition:
        any of them
}
