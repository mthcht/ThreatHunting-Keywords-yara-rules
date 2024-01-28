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
        $string1 = /\sinceptor\..{0,1000}dotnet/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string2 = /\sinceptor\.py/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string3 = /\sinceptor\.py/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string4 = /\sinceptor\.spec/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string5 = /\s\-\-obfuscate\s/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string6 = /\s\-\-pinject\s/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string7 = /\s\-\-sign\-domain\s/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string8 = /\s\-\-sign\-steal\s/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string9 = /\s\-t\sdonut\s/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string10 = /\s\-t\spe2sh/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string11 = /\s\-\-transformer\sdonut/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string12 = /\s\-\-transformer\sLoader/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string13 = /\s\-\-transformer\spe2sh/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string14 = /\s\-\-transformer\ssRDI/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string15 = /\.\/inceptor\.py/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string16 = /\/csharp\/process_injection\// nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string17 = /\/inceptor\.git/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string18 = /\/inceptor\.git/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string19 = /\/Obfuscator\.py/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string20 = /\/Obfuscator\.py/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string21 = /\/powershell\/process_injection\// nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string22 = /\/syscalls\/syswhispers\// nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string23 = /\/syscalls\/syswhispersv2/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string24 = /\/syswhispersv2/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string25 = /\\inceptor\.py/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string26 = /\\pe2sh\.exe/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string27 = /\]\sFetching\sLLVM\-Obfuscator\s\?/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string28 = /AesEncryptor\.py/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string29 = /AsStrongAsFuck\.exe/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string30 = /AsStrongAsFuck\.py/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string31 = /bypass\-classic\.dll/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string32 = /BYPASS\-DINVOKE.{0,1000}\.dll/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string33 = /BYPASS\-DINVOKE\.dll/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string34 = /BYPASS\-DINVOKE_MANUAL_MAPPING\.dll/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string35 = /bypass\-powershell\.ps1/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string36 = /cd\sinceptor/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string37 = /chameleon\.py\s/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string38 = /chunlie\.exe/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string39 = /cloc\.exe\s\-\-exclude\-dir/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string40 = /Confuser\.CLI\.exe/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string41 = /Confuser\.DynCipher\.dll/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string42 = /Confuser\.Renamer\.dll/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string43 = /DotNetArtifactGenerator\.py/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string44 = /frida\-trace\s\-x\sntdll\.dll\s\-i\s.{0,1000}\s\-p\s/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string45 = /inceptor.{0,1000}POWERSHELL/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string46 = /inceptor\.py\s/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string47 = /inceptor\/obfuscators/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string48 = /inceptor\-main\.zip/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string49 = /Invoke\-AmsiBypass/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string50 = /Invoke\-IronCyclone/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string51 = /Invoke\-PsUACme/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string52 = /Karmaleon\.py/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string53 = /klezVirus\/inceptor/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string54 = /mimikatz\.raw/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string55 = /msf\-revhttps/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string56 = /msf\-sgn\.raw/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string57 = /pe2sh\.exe/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string58 = /Pe2Shellcode\.py/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string59 = /PowerShellArtifactGenerator\.py/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string60 = /Rubeus\.bin/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string61 = /SharpConfigParser\.dll/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string62 = /SigThief\.py/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string63 = /steal\-cert\.py/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string64 = /syswhispers\.py/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string65 = /syswhispers\.py/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string66 = /syswhispersv2_x86/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string67 = /ThreatCheck\.exe/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string68 = /winexec\.notepad\.raw/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string69 = /XorEncoder\.py/ nocase ascii wide
        // Description: Template-Driven AV/EDR Evasion Framework
        // Reference: https://github.com/klezVirus/inceptor
        $string70 = /inceptor.{0,1000}dotnet/ nocase ascii wide

    condition:
        any of them
}
