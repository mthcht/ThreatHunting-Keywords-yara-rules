rule HellsGate
{
    meta:
        description = "Detection patterns for the tool 'HellsGate' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HellsGate"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The Hell's Gate technique is a method employed by malware to hide its malicious behavior and avoid detection. This technique involves executing system calls directly thus bypassing the Windows API (Application Programming Interface) which is typically monitored by EDRs
        // Reference: https://github.com/am0nsec/HellsGate
        $string1 = /\/HellsGate\.git/ nocase ascii wide
        // Description: The Hell's Gate technique is a method employed by malware to hide its malicious behavior and avoid detection. This technique involves executing system calls directly thus bypassing the Windows API (Application Programming Interface) which is typically monitored by EDRs
        // Reference: https://github.com/am0nsec/HellsGate
        $string2 = /am0nsec\/HellsGate/ nocase ascii wide
        // Description: The Hell's Gate technique is a method employed by malware to hide its malicious behavior and avoid detection. This technique involves executing system calls directly thus bypassing the Windows API (Application Programming Interface) which is typically monitored by EDRs
        // Reference: https://github.com/am0nsec/HellsGate
        $string3 = /DC6187CB\-D5DF\-4973\-84A2\-F92AAE90CDA9/ nocase ascii wide
        // Description: The Hell's Gate technique is a method employed by malware to hide its malicious behavior and avoid detection. This technique involves executing system calls directly thus bypassing the Windows API (Application Programming Interface) which is typically monitored by EDRs
        // Reference: https://github.com/am0nsec/HellsGate
        $string4 = /hellsgate\.asm/ nocase ascii wide
        // Description: The Hell's Gate technique is a method employed by malware to hide its malicious behavior and avoid detection. This technique involves executing system calls directly thus bypassing the Windows API (Application Programming Interface) which is typically monitored by EDRs
        // Reference: https://github.com/am0nsec/HellsGate
        $string5 = /HellsGate\.exe/ nocase ascii wide
        // Description: The Hell's Gate technique is a method employed by malware to hide its malicious behavior and avoid detection. This technique involves executing system calls directly thus bypassing the Windows API (Application Programming Interface) which is typically monitored by EDRs
        // Reference: https://github.com/am0nsec/HellsGate
        $string6 = /HellsGate\.sln/ nocase ascii wide
        // Description: The Hell's Gate technique is a method employed by malware to hide its malicious behavior and avoid detection. This technique involves executing system calls directly thus bypassing the Windows API (Application Programming Interface) which is typically monitored by EDRs
        // Reference: https://github.com/am0nsec/HellsGate
        $string7 = /HellsGate\.vcxproj/ nocase ascii wide

    condition:
        any of them
}
