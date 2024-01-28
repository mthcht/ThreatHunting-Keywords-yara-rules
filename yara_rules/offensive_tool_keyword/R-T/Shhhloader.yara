rule Shhhloader
{
    meta:
        description = "Detection patterns for the tool 'Shhhloader' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shhhloader"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: shellcode loader that compiles a C++ stub to bypass AV/EDR
        // Reference: https://github.com/icyguider/Shhhloader
        $string1 = /\sShhhavoc\.py/ nocase ascii wide
        // Description: shellcode loader that compiles a C++ stub to bypass AV/EDR
        // Reference: https://github.com/icyguider/Shhhloader
        $string2 = /\/Shhhavoc\.py/ nocase ascii wide
        // Description: shellcode loader that compiles a C++ stub to bypass AV/EDR
        // Reference: https://github.com/icyguider/Shhhloader
        $string3 = /\/Shhhloader\.git/ nocase ascii wide
        // Description: shellcode loader that compiles a C++ stub to bypass AV/EDR
        // Reference: https://github.com/icyguider/Shhhloader
        $string4 = /\[\+\]\sICYGUIDER\'S\sCUSTOM\sSYSCALL\sSHELLCODE\sLOADER/ nocase ascii wide
        // Description: shellcode loader that compiles a C++ stub to bypass AV/EDR
        // Reference: https://github.com/icyguider/Shhhloader
        $string5 = /\[\+\]\sInjecting\sinto\sexisting\sprocess/ nocase ascii wide
        // Description: shellcode loader that compiles a C++ stub to bypass AV/EDR
        // Reference: https://github.com/icyguider/Shhhloader
        $string6 = /\[\+\]\sUsing\sDLL\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
        // Description: shellcode loader that compiles a C++ stub to bypass AV/EDR
        // Reference: https://github.com/icyguider/Shhhloader
        $string7 = /\[\+\]\sUsing\sdomain\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
        // Description: shellcode loader that compiles a C++ stub to bypass AV/EDR
        // Reference: https://github.com/icyguider/Shhhloader
        $string8 = /\[\+\]\sUsing\shostname\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
        // Description: shellcode loader that compiles a C++ stub to bypass AV/EDR
        // Reference: https://github.com/icyguider/Shhhloader
        $string9 = /\[\+\]\sUsing\sObfuscator\-LLVM\sto\scompile\sstub/ nocase ascii wide
        // Description: shellcode loader that compiles a C++ stub to bypass AV/EDR
        // Reference: https://github.com/icyguider/Shhhloader
        $string10 = /\[\+\]\sUsing\ssleep\stechnique\sfor\ssandbox\sevasion/ nocase ascii wide
        // Description: shellcode loader that compiles a C++ stub to bypass AV/EDR
        // Reference: https://github.com/icyguider/Shhhloader
        $string11 = /\[\+\]\sUsing\sSysWhispers2\sfor\ssyscalls/ nocase ascii wide
        // Description: shellcode loader that compiles a C++ stub to bypass AV/EDR
        // Reference: https://github.com/icyguider/Shhhloader
        $string12 = /\[\+\]\sUsing\sSysWhispers3\sfor\ssyscalls/ nocase ascii wide
        // Description: shellcode loader that compiles a C++ stub to bypass AV/EDR
        // Reference: https://github.com/icyguider/Shhhloader
        $string13 = /\\Shhhavoc\.py/ nocase ascii wide
        // Description: shellcode loader that compiles a C++ stub to bypass AV/EDR
        // Reference: https://github.com/icyguider/Shhhloader
        $string14 = /icyguider\/Shhhloader/ nocase ascii wide
        // Description: shellcode loader that compiles a C++ stub to bypass AV/EDR
        // Reference: https://github.com/icyguider/Shhhloader
        $string15 = /Shhhavoc\.py\s/ nocase ascii wide
        // Description: shellcode loader that compiles a C++ stub to bypass AV/EDR
        // Reference: https://github.com/icyguider/Shhhloader
        $string16 = /Shhhloader\.py/ nocase ascii wide
        // Description: shellcode loader that compiles a C++ stub to bypass AV/EDR
        // Reference: https://github.com/icyguider/Shhhloader
        $string17 = /Shhhloader\-main\\/ nocase ascii wide

    condition:
        any of them
}
