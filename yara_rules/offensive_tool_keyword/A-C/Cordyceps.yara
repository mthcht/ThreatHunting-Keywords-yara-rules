rule Cordyceps
{
    meta:
        description = "Detection patterns for the tool 'Cordyceps' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cordyceps"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C++ self-Injecting dropper based on various EDR evasion techniques
        // Reference: https://github.com/pard0p/Cordyceps
        $string1 = /\/Cordyceps\.git/ nocase ascii wide
        // Description: C++ self-Injecting dropper based on various EDR evasion techniques
        // Reference: https://github.com/pard0p/Cordyceps
        $string2 = /cordyceps\.exe/ nocase ascii wide
        // Description: C++ self-Injecting dropper based on various EDR evasion techniques
        // Reference: https://github.com/pard0p/Cordyceps
        $string3 = /Cordyceps\-main\.zip/ nocase ascii wide
        // Description: C++ self-Injecting dropper based on various EDR evasion techniques
        // Reference: https://github.com/pard0p/Cordyceps
        $string4 = /nasm\s\-f\swin64\s\.\/syscalls\.asm\s\-o\s\.\/syscalls\.obj/ nocase ascii wide
        // Description: C++ self-Injecting dropper based on various EDR evasion techniques
        // Reference: https://github.com/pard0p/Cordyceps
        $string5 = /pard0p\/Cordyceps/ nocase ascii wide

    condition:
        any of them
}
