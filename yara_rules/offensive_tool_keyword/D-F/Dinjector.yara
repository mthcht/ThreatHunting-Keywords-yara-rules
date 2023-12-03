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
        $string1 = /.{0,1000}\/cradle\.ps1.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string2 = /.{0,1000}\/DInjector\.git.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string3 = /.{0,1000}\/pid:1337\s.{0,1000}\/dll:.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string4 = /.{0,1000}\\cradle\.ps1.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string5 = /.{0,1000}\\DInjector\.sln.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string6 = /.{0,1000}\\DInjector\\.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string7 = /.{0,1000}5086CE01\-1032\-4CA3\-A302\-6CFF2A8B64DC.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string8 = /.{0,1000}creds_hunt\.exe.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string9 = /.{0,1000}DInjector\.csproj.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string10 = /.{0,1000}DInjector\.Detonator.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string11 = /.{0,1000}DInjector\.dll.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string12 = /.{0,1000}DInjector\/Dinjector.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string13 = /.{0,1000}Dinjector\-main.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string14 = /.{0,1000}DllCanUnloadNow.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string15 = /.{0,1000}encrypt\.py\s.{0,1000}\.bin\s\-p\s.{0,1000}\s\-o\s.{0,1000}\.enc.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string16 = /.{0,1000}\-\-entrypoint\sDinjector.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string17 = /.{0,1000}http:\/\/10\.10\.13\.37.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string18 = /.{0,1000}KeeFarceReborn\..{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string19 = /.{0,1000}Metro\-Holografix\/Dinjector.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string20 = /.{0,1000}NtCreateUserProcessShellcode.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string21 = /.{0,1000}PIC\-Exec.{0,1000}runshellcode\.asm.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string22 = /.{0,1000}PIC\-Exec\\addresshunter.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string23 = /.{0,1000}win\-x64\-DynamicKernelWinExecCalc.{0,1000}/ nocase ascii wide
        // Description: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // Reference: https://github.com/Metro-Holografix/DInjector
        $string24 = /.{0,1000}x64win\-DynamicNoNull\-WinExec\-PopCalc\-Shellcode.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
