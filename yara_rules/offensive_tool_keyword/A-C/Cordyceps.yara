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
        $string1 = /.{0,1000}\/Cordyceps\.git.{0,1000}/ nocase ascii wide
        // Description: C++ self-Injecting dropper based on various EDR evasion techniques
        // Reference: https://github.com/pard0p/Cordyceps
        $string2 = /.{0,1000}cordyceps\.exe.{0,1000}/ nocase ascii wide
        // Description: C++ self-Injecting dropper based on various EDR evasion techniques
        // Reference: https://github.com/pard0p/Cordyceps
        $string3 = /.{0,1000}Cordyceps\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: C++ self-Injecting dropper based on various EDR evasion techniques
        // Reference: https://github.com/pard0p/Cordyceps
        $string4 = /.{0,1000}nasm\s\-f\swin64\s\.\/syscalls\.asm\s\-o\s\.\/syscalls\.obj.{0,1000}/ nocase ascii wide
        // Description: C++ self-Injecting dropper based on various EDR evasion techniques
        // Reference: https://github.com/pard0p/Cordyceps
        $string5 = /.{0,1000}pard0p\/Cordyceps.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
