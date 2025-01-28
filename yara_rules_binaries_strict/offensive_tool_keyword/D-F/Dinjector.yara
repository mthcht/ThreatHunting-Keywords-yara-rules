rule Dinjector
{
    meta:
        description = "Detection patterns for the tool 'Dinjector' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dinjector"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string1 = /\/cradle\.ps1/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string2 = /\/DInjector\.git/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string3 = /\/pid\:1337\s.{0,100}\/dll\:/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string4 = /\\cradle\.ps1/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string5 = /\\DInjector\.sln/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string6 = /\\DInjector\\/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string7 = "5086CE01-1032-4CA3-A302-6CFF2A8B64DC" nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string8 = /creds_hunt\.exe/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string9 = /DInjector\.csproj/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string10 = /DInjector\.Detonator/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string11 = /DInjector\.dll/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string12 = "DInjector/Dinjector" nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string13 = "Dinjector-main" nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string14 = /encrypt\.py\s.{0,100}\.bin\s\-p\s.{0,100}\s\-o\s.{0,100}\.enc/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string15 = "--entrypoint Dinjector" nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string16 = /http\:\/\/10\.10\.13\.37/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string17 = /KeeFarceReborn\./ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string18 = "Metro-Holografix/Dinjector" nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string19 = "NtCreateUserProcessShellcode" nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string20 = /PIC\-Exec.{0,100}runshellcode\.asm/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string21 = /PIC\-Exec\\addresshunter/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string22 = "win-x64-DynamicKernelWinExecCalc" nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string23 = "x64win-DynamicNoNull-WinExec-PopCalc-Shellcode" nocase ascii wide
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
