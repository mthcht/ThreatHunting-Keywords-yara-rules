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
        $string6 = /\[\+\]\sInjected\sthe\s.{0,100}\sDLL\sinto\sprocess\s/ nocase ascii wide
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
