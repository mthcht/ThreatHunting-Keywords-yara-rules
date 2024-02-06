rule KaynLdr
{
    meta:
        description = "Detection patterns for the tool 'KaynLdr' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KaynLdr"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string1 = /\sKaynInject\.h/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string2 = /\/KaynLdr\.git/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string3 = /\[\-\]\sCouldn\'t\schange\smemory\sprotection\sfrom\sRW\sto\sRX/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string4 = /\[\-\]\sCouldn\'t\scopy\sdll\sbuffer/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string5 = /\[\-\]\sCouldn\'t\sfind\sKaynLoader/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string6 = /\[\+\]\sInjected\sthe\s.{0,1000}\sDLL\sinto\sprocess\s/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string7 = /\[\+\]\sSuccessful\sallocated\sremote\smemory\:\slpRemoteLibraryBuffer\:\[/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string8 = /\[\+\]\sSuccessful\schange\sprotection\:\sRW\s\-\>\sRX/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string9 = /\[\+\]\sSuccessful\scopied\sdll\sbuffer/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string10 = /\[\+\]\sSuccessful\sinjected\sDLL\:\shThread\:/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string11 = /\\KaynInject\.h/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string12 = /\\KaynLdr\\KaynInject\\/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string13 = /\\KaynLdr\-main\\/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string14 = /\\src\\KaynInject\.c/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string15 = /\\src\\KaynLdr\.c/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string16 = /Call\sKaynLoader\sin\sa\sremote\sthread/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string17 = /Call\sKaynLoader\sin\sa\sremote\sthread/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string18 = /Cracked5pider\/KaynLdr/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string19 = /Hello\sfrom\sKaynLdr/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string20 = /KaynInject\.x64\.exe/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string21 = /KaynInject\.x86\.exe/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string22 = /KAYNINJECT_KAYNINJECT_H/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string23 = /KaynLdr\.x64\.dll/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string24 = /KAYNLDR_KAYNLDR_H/ nocase ascii wide
        // Description: KaynLdr is a Reflective Loader written in C/ASM
        // Reference: https://github.com/Cracked5pider/KaynLdr
        $string25 = /Write\sDll\sbuffer\sinto\sremote\smemory/ nocase ascii wide

    condition:
        any of them
}
