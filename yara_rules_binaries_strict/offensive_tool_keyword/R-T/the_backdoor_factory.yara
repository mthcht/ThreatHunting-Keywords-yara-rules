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
        $string2 = /\s\-f\s.{0,100}\.exe\s\-m\sonionduke\s\-b\s.{0,100}\.dll/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string3 = /\s\-f\s.{0,100}\.exe\s\-m\sonionduke\s\-b\s.{0,100}\.exe/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string4 = /\s\-f\spsexec\.exe\s\-H\s.{0,100}\s\-P\s.{0,100}\s\-s\sreverse_shell_tcp/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string5 = /\s\-f\stcpview\.exe\s\-s\siat_reverse_tcp_inline\s\-H\s.{0,100}\s\-P\s.{0,100}\s\-m\sautomatic\s\-C/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string6 = /\s\-f\sTeamViewer\.exe\s\-H\s.{0,100}\s\-P\s.{0,100}\s\-s\s/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string7 = /\s\-i\s\-H\s.{0,100}\s\-P\s.{0,100}\s\-s\sreverse_shell_tcp\s\-a\s\-u\s\.moocowwow/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string8 = " install backdoor-factory" nocase ascii wide
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
        $string16 = "5b36e42494ab562f7adb9c5dbf17761300050efd24c1c9c61dcb82e5bb628840" nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string17 = "9d0ff36d92bb6cac9255111b4af63700c5e796fe8233504b4acd1ec4f92bb43f" nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string18 = "baf6deb599ee2e6cd817dbc447bdb4ea3cf9a585708c8c585f9a104ffba2b8d9" nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string19 = "d4aae162571f8338f2560eb32b774647fd0f1952d901dd38f8685e42ceeea813" nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string20 = /LinuxARMLELF32\.py/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string21 = /loadliba_reverse_tcp\.asm/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string22 = /loadliba_shell\.asm/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string23 = /loadliba_single_shell_reverse_tcp\.asm/ nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string24 = "secretsquirrel/the-backdoor-factory" nocase ascii wide
        // Description: Patch PE  ELF  Mach-O binaries with shellcode new version in development*
        // Reference: https://github.com/secretsquirrel/the-backdoor-factory
        $string25 = "the-backdoor-factory-master" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
