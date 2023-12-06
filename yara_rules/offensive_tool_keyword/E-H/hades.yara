rule hades
{
    meta:
        description = "Detection patterns for the tool 'hades' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hades"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string1 = /\.exe.{0,1000}\s\-f\s.{0,1000}\.bin\s\-t\squeueuserapc/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string2 = /\.exe.{0,1000}\s\-t\squeueuserapc/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string3 = /\.exe.{0,1000}\s\-t\sremotethread/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string4 = /\.exe.{0,1000}\s\-t\sselfthread/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string5 = /\.exe.{0,1000}\s\-\-technique\squeueuserapc/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string6 = /\.exe.{0,1000}\s\-\-technique\sremotethread/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string7 = /\.exe.{0,1000}\s\-\-technique\sselfthread/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string8 = /\/cmd\/hades\// nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string9 = /\/hades\.git/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string10 = /\/hades\-main\.zip/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string11 = /\\hades\.exe/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string12 = /\\hades\-main\.zip/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string13 = /f1zm0\/hades/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string14 = /hades_directsys\.exe/ nocase ascii wide

    condition:
        any of them
}
