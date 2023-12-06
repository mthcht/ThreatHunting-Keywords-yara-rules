rule Nimcrypt2
{
    meta:
        description = "Detection patterns for the tool 'Nimcrypt2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nimcrypt2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: .NET PE & Raw Shellcode Packer/Loader Written in Nim
        // Reference: https://github.com/icyguider/Nimcrypt2
        $string1 = /\s\-\-get\-syscallstub\s/ nocase ascii wide
        // Description: .NET PE & Raw Shellcode Packer/Loader Written in Nim
        // Reference: https://github.com/icyguider/Nimcrypt2
        $string2 = /\s\-\-llvm\-obfuscator\s.{0,1000}\s/ nocase ascii wide
        // Description: .NET PE & Raw Shellcode Packer/Loader Written in Nim
        // Reference: https://github.com/icyguider/Nimcrypt2
        $string3 = /\/Nimcrypt2/ nocase ascii wide
        // Description: .NET PE & Raw Shellcode Packer/Loader Written in Nim
        // Reference: https://github.com/icyguider/Nimcrypt2
        $string4 = /GetSyscallStub\.nim/ nocase ascii wide
        // Description: .NET PE & Raw Shellcode Packer/Loader Written in Nim
        // Reference: https://github.com/icyguider/Nimcrypt2
        $string5 = /nimcrypt\s\-/ nocase ascii wide
        // Description: .NET PE & Raw Shellcode Packer/Loader Written in Nim
        // Reference: https://github.com/icyguider/Nimcrypt2
        $string6 = /nimcrypt\.nim/ nocase ascii wide
        // Description: .NET PE & Raw Shellcode Packer/Loader Written in Nim
        // Reference: https://github.com/icyguider/Nimcrypt2
        $string7 = /syscalls\.nim/ nocase ascii wide

    condition:
        any of them
}
