rule the_backdoor_factory
{
    meta:
        description = "Detection patterns for the tool 'the-backdoor-factory' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "the-backdoor-factory"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Patch PE ELF Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string1 = /\sbackdoor\.py/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string2 = /\s\-f\s.{0,1000}\.exe\s\-m\sonionduke\s\-b\s.{0,1000}\.dll/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string3 = /\s\-f\s.{0,1000}\.exe\s\-m\sonionduke\s\-b\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string4 = /\s\-f\spsexec\.exe\s\-H\s.{0,1000}\s\-P\s.{0,1000}\s\-s\sreverse_shell_tcp/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string5 = /\s\-f\stcpview\.exe\s\-s\siat_reverse_tcp_inline\s\-H\s.{0,1000}\s\-P\s.{0,1000}\s\-m\sautomatic\s\-C/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string6 = /\s\-f\sTeamViewer\.exe\s\-H\s.{0,1000}\s\-P\s.{0,1000}\s\-s\s/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string7 = /\s\-i\s\-H\s.{0,1000}\s\-P\s.{0,1000}\s\-s\sreverse_shell_tcp\s\-a\s\-u\s\.moocowwow/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string8 = /\sinstall\sbackdoor\-factory/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string9 = /\spayloadtests\.py/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string10 = /\/backdoor\.py/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string11 = /\/payloadtests\.py/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string12 = /\/the\-backdoor\-factory\.git/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string13 = /\\backdoored\\/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string14 = /\\payloadtests\.py/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string15 = /\\the\-backdoor\-factory\\/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string16 = /LinuxARMLELF32\.py/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string17 = /loadliba_reverse_tcp\.asm/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string18 = /loadliba_shell\.asm/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string19 = /loadliba_single_shell_reverse_tcp\.asm/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string20 = /secretsquirrel\/the\-backdoor\-factory/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string21 = /the\-backdoor\-factory\-master/ nocase ascii wide

    condition:
        any of them
}
