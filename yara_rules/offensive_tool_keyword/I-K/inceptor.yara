rule inceptor
{
    meta:
        description = "Detection patterns for the tool 'inceptor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "inceptor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string1 = /.{0,1000}\sinceptor\..{0,1000}dotnet.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string2 = /.{0,1000}\sinceptor\.py.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string3 = /.{0,1000}\sinceptor\.py.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string4 = /.{0,1000}\sinceptor\.spec.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string5 = /.{0,1000}\s\-\-obfuscate\s.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string6 = /.{0,1000}\s\-\-pinject\s.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string7 = /.{0,1000}\s\-\-sign\-domain\s.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string8 = /.{0,1000}\s\-\-sign\-steal\s.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string9 = /.{0,1000}\s\-t\sdonut\s.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string10 = /.{0,1000}\s\-t\spe2sh.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string11 = /.{0,1000}\s\-\-transformer\sdonut.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string12 = /.{0,1000}\s\-\-transformer\sLoader.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string13 = /.{0,1000}\s\-\-transformer\spe2sh.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string14 = /.{0,1000}\s\-\-transformer\ssRDI.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string15 = /.{0,1000}\.\/inceptor\.py.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string16 = /.{0,1000}\/csharp\/process_injection\/.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string17 = /.{0,1000}\/inceptor\.git.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string18 = /.{0,1000}\/inceptor\.git.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string19 = /.{0,1000}\/Obfuscator\.py.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string20 = /.{0,1000}\/Obfuscator\.py.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string21 = /.{0,1000}\/powershell\/process_injection\/.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string22 = /.{0,1000}\/syscalls\/syswhispers\/.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string23 = /.{0,1000}\/syscalls\/syswhispersv2.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string24 = /.{0,1000}\/syswhispersv2.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string25 = /.{0,1000}\\inceptor\.py.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string26 = /.{0,1000}AesEncryptor\.py.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string27 = /.{0,1000}AsStrongAsFuck\.exe.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string28 = /.{0,1000}AsStrongAsFuck\.py.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string29 = /.{0,1000}bypass\-classic\.dll.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string30 = /.{0,1000}BYPASS\-DINVOKE.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string31 = /.{0,1000}BYPASS\-DINVOKE\.dll.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string32 = /.{0,1000}BYPASS\-DINVOKE_MANUAL_MAPPING\.dll.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string33 = /.{0,1000}bypass\-powershell\.ps1.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string34 = /.{0,1000}cd\sinceptor.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string35 = /.{0,1000}chameleon\.py\s.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string36 = /.{0,1000}chunlie\.exe.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string37 = /.{0,1000}cloc\.exe\s\-\-exclude\-dir.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string38 = /.{0,1000}Confuser\.CLI\.exe.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string39 = /.{0,1000}Confuser\.DynCipher\.dll.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string40 = /.{0,1000}Confuser\.Renamer\.dll.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string41 = /.{0,1000}DotNetArtifactGenerator\.py.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string42 = /.{0,1000}frida\-trace\s\-x\sntdll\.dll\s\-i\s.{0,1000}\s\-p\s.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string43 = /.{0,1000}inceptor.{0,1000}POWERSHELL.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string44 = /.{0,1000}inceptor\.py\s.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string45 = /.{0,1000}inceptor\/obfuscators.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string46 = /.{0,1000}inceptor\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string47 = /.{0,1000}Invoke\-AmsiBypass.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string48 = /.{0,1000}Invoke\-IronCyclone.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string49 = /.{0,1000}Invoke\-PsUACme.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string50 = /.{0,1000}Karmaleon\.py.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string51 = /.{0,1000}klezVirus\/inceptor.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string52 = /.{0,1000}mimikatz\.raw.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string53 = /.{0,1000}msf\-revhttps.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string54 = /.{0,1000}msf\-sgn\.raw.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string55 = /.{0,1000}pe2sh\.exe.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string56 = /.{0,1000}Pe2Shellcode\.py.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string57 = /.{0,1000}PowerShellArtifactGenerator\.py.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string58 = /.{0,1000}Rubeus\.bin.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string59 = /.{0,1000}SharpConfigParser\.dll.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string60 = /.{0,1000}SigThief\.py.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string61 = /.{0,1000}steal\-cert\.py.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string62 = /.{0,1000}syswhispers\.py.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string63 = /.{0,1000}syswhispers\.py.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string64 = /.{0,1000}syswhispersv2_x86.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string65 = /.{0,1000}ThreatCheck\.exe.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string66 = /.{0,1000}winexec\.notepad\.raw.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string67 = /.{0,1000}XorEncoder\.py.{0,1000}/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string68 = /inceptor.{0,1000}dotnet.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
