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
        $string1 = /\s\-\-shellcode\s/ nocase ascii wide
        // Description: PE Binary Shellcode Injector - Automated code cave discovery. shellcode injection - ASLR bypass - x86/x64 compatible
        // Reference: https://github.com/ins1gn1a/Frampton
        $string2 = /\.exe\s\-s\s.{0,1000}\\x.{0,1000}\\x.{0,1000}\\x/ nocase ascii wide
        // Description: PE Binary Shellcode Injector - Automated code cave discovery. shellcode injection - ASLR bypass - x86/x64 compatible
        // Reference: https://github.com/ins1gn1a/Frampton
        $string3 = /\.py\s\-f\s.{0,1000}\.exe\s\-e\s\-m\s4/ nocase ascii wide
        // Description: PE Binary Shellcode Injector - Automated code cave discovery. shellcode injection - ASLR bypass - x86/x64 compatible
        // Reference: https://github.com/ins1gn1a/Frampton
        $string4 = /_backdoor\.exe/ nocase ascii wide
        // Description: PE Binary Shellcode Injector - Automated code cave discovery. shellcode injection - ASLR bypass - x86/x64 compatible
        // Reference: https://github.com/ins1gn1a/Frampton
        $string5 = /Disabling\sASLR\s/ nocase ascii wide
        // Description: PE Binary Shellcode Injector - Automated code cave discovery. shellcode injection - ASLR bypass - x86/x64 compatible
        // Reference: https://github.com/ins1gn1a/Frampton
        $string6 = /frampton\.py/ nocase ascii wide
        // Description: PE Binary Shellcode Injector - Automated code cave discovery. shellcode injection - ASLR bypass - x86/x64 compatible
        // Reference: https://github.com/ins1gn1a/Frampton
        $string7 = /ins1gn1a\/Frampton/ nocase ascii wide

    condition:
        any of them
}
