rule the_backdoor_factory
{
    meta:
        description = "Detection patterns for the tool 'the-backdoor-factory' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "the-backdoor-factory"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string1 = /.{0,1000}\sbackdoor\.py.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string2 = /.{0,1000}\s\-f\s.{0,1000}\.exe\s\-m\sonionduke\s\-b\s.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string3 = /.{0,1000}\s\-f\s.{0,1000}\.exe\s\-m\sonionduke\s\-b\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string4 = /.{0,1000}\s\-f\spsexec\.exe\s\-H\s.{0,1000}\s\-P\s.{0,1000}\s\-s\sreverse_shell_tcp.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string5 = /.{0,1000}\s\-f\stcpview\.exe\s\-s\siat_reverse_tcp_inline\s\-H\s.{0,1000}\s\-P\s.{0,1000}\s\-m\sautomatic\s\-C.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string6 = /.{0,1000}\s\-f\sTeamViewer\.exe\s\-H\s.{0,1000}\s\-P\s.{0,1000}\s\-s\s.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string7 = /.{0,1000}\s\-i\s\-H\s.{0,1000}\s\-P\s.{0,1000}\s\-s\sreverse_shell_tcp\s\-a\s\-u\s\.moocowwow.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string8 = /.{0,1000}\sinstall\sbackdoor\-factory.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string9 = /.{0,1000}\spayloadtests\.py.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string10 = /.{0,1000}\/backdoor\.py.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string11 = /.{0,1000}\/payloadtests\.py.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string12 = /.{0,1000}\/the\-backdoor\-factory\.git.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string13 = /.{0,1000}\\backdoored\\.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string14 = /.{0,1000}\\payloadtests\.py.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string15 = /.{0,1000}\\the\-backdoor\-factory\\.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string16 = /.{0,1000}LinuxARMLELF32\.py.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string17 = /.{0,1000}loadliba_reverse_tcp\.asm.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string18 = /.{0,1000}loadliba_shell\.asm.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string19 = /.{0,1000}loadliba_single_shell_reverse_tcp\.asm.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string20 = /.{0,1000}secretsquirrel\/the\-backdoor\-factory.{0,1000}/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string21 = /.{0,1000}the\-backdoor\-factory\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
