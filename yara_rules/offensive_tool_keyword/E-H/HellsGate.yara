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
        $string1 = /.{0,1000}\/HellsGate\.git.{0,1000}/ nocase ascii wide
        // Description: The Hell's Gate technique is a method employed by malware to hide its malicious behavior and avoid detection. This technique involves executing system calls directly thus bypassing the Windows API (Application Programming Interface) which is typically monitored by EDRs
        // Reference: https://github.com/am0nsec/HellsGate
        $string2 = /.{0,1000}am0nsec\/HellsGate.{0,1000}/ nocase ascii wide
        // Description: The Hell's Gate technique is a method employed by malware to hide its malicious behavior and avoid detection. This technique involves executing system calls directly thus bypassing the Windows API (Application Programming Interface) which is typically monitored by EDRs
        // Reference: https://github.com/am0nsec/HellsGate
        $string3 = /.{0,1000}hellsgate\.asm.{0,1000}/ nocase ascii wide
        // Description: The Hell's Gate technique is a method employed by malware to hide its malicious behavior and avoid detection. This technique involves executing system calls directly thus bypassing the Windows API (Application Programming Interface) which is typically monitored by EDRs
        // Reference: https://github.com/am0nsec/HellsGate
        $string4 = /.{0,1000}HellsGate\.exe.{0,1000}/ nocase ascii wide
        // Description: The Hell's Gate technique is a method employed by malware to hide its malicious behavior and avoid detection. This technique involves executing system calls directly thus bypassing the Windows API (Application Programming Interface) which is typically monitored by EDRs
        // Reference: https://github.com/am0nsec/HellsGate
        $string5 = /.{0,1000}HellsGate\.sln.{0,1000}/ nocase ascii wide
        // Description: The Hell's Gate technique is a method employed by malware to hide its malicious behavior and avoid detection. This technique involves executing system calls directly thus bypassing the Windows API (Application Programming Interface) which is typically monitored by EDRs
        // Reference: https://github.com/am0nsec/HellsGate
        $string6 = /.{0,1000}HellsGate\.vcxproj.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
