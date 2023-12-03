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
        $string1 = /.{0,1000}\.exe.{0,1000}\s\-f\s.{0,1000}\.bin\s\-t\squeueuserapc.{0,1000}/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string2 = /.{0,1000}\.exe.{0,1000}\s\-t\squeueuserapc.{0,1000}/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string3 = /.{0,1000}\.exe.{0,1000}\s\-t\sremotethread.{0,1000}/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string4 = /.{0,1000}\.exe.{0,1000}\s\-t\sselfthread.{0,1000}/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string5 = /.{0,1000}\.exe.{0,1000}\s\-\-technique\squeueuserapc.{0,1000}/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string6 = /.{0,1000}\.exe.{0,1000}\s\-\-technique\sremotethread.{0,1000}/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string7 = /.{0,1000}\.exe.{0,1000}\s\-\-technique\sselfthread.{0,1000}/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string8 = /.{0,1000}\/cmd\/hades\/.{0,1000}/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string9 = /.{0,1000}\/hades\.git.{0,1000}/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string10 = /.{0,1000}\/hades\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string11 = /.{0,1000}\\hades\.exe.{0,1000}/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string12 = /.{0,1000}\\hades\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string13 = /.{0,1000}f1zm0\/hades.{0,1000}/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string14 = /.{0,1000}hades_directsys\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
