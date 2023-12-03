rule frampton
{
    meta:
        description = "Detection patterns for the tool 'frampton' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "frampton"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PE Binary Shellcode Injector - Automated code cave discovery. shellcode injection - ASLR bypass - x86/x64 compatible
        // Reference: https://github.com/ins1gn1a/Frampton
        $string1 = /.{0,1000}\s\-\-shellcode\s.{0,1000}/ nocase ascii wide
        // Description: PE Binary Shellcode Injector - Automated code cave discovery. shellcode injection - ASLR bypass - x86/x64 compatible
        // Reference: https://github.com/ins1gn1a/Frampton
        $string2 = /.{0,1000}\.exe\s\-s\s.{0,1000}\\x.{0,1000}\\x.{0,1000}\\x.{0,1000}/ nocase ascii wide
        // Description: PE Binary Shellcode Injector - Automated code cave discovery. shellcode injection - ASLR bypass - x86/x64 compatible
        // Reference: https://github.com/ins1gn1a/Frampton
        $string3 = /.{0,1000}\.py\s\-f\s.{0,1000}\.exe\s\-e\s\-m\s4/ nocase ascii wide
        // Description: PE Binary Shellcode Injector - Automated code cave discovery. shellcode injection - ASLR bypass - x86/x64 compatible
        // Reference: https://github.com/ins1gn1a/Frampton
        $string4 = /.{0,1000}_backdoor\.exe.{0,1000}/ nocase ascii wide
        // Description: PE Binary Shellcode Injector - Automated code cave discovery. shellcode injection - ASLR bypass - x86/x64 compatible
        // Reference: https://github.com/ins1gn1a/Frampton
        $string5 = /.{0,1000}Disabling\sASLR\s.{0,1000}/ nocase ascii wide
        // Description: PE Binary Shellcode Injector - Automated code cave discovery. shellcode injection - ASLR bypass - x86/x64 compatible
        // Reference: https://github.com/ins1gn1a/Frampton
        $string6 = /.{0,1000}frampton\.py.{0,1000}/ nocase ascii wide
        // Description: PE Binary Shellcode Injector - Automated code cave discovery. shellcode injection - ASLR bypass - x86/x64 compatible
        // Reference: https://github.com/ins1gn1a/Frampton
        $string7 = /.{0,1000}ins1gn1a\/Frampton.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
