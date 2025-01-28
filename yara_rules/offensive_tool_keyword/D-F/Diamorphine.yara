rule Diamorphine
{
    meta:
        description = "Detection patterns for the tool 'Diamorphine' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Diamorphine"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string1 = /\sdiamorphine\.c/
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string2 = /\sdiamorphine\.h/
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string3 = " hacked_getdents"
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string4 = /\/Diamorphine\.git/
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string5 = /\\diamorphine\.c/
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string6 = /\\diamorphine\.h/
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string7 = "5d637915abc98b21f94b0648c552899af67321ab06fb34e33339ae38401734cf"
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string8 = "b7b5637287f143fe5e54c022e6c7b785141cfdeec2aceac263ee38e5ac17d3d7"
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string9 = "f0e1e5a2b52773889dc1e7c44c5a80716a0dd98beee46b705748773e292e1d88"
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string10 = /hacked_getdents64\(/
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string11 = /hacked_kill\(/
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string12 = /LKM_HACKING\.html/
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string13 = "m0nad/Diamorphine"
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string14 = "MAGIC_PREFIX \"diamorphine_secret"
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string15 = /MODULE_AUTHOR\(\\"m0nad\\"\)/
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string16 = /MODULE_DESCRIPTION\(\\"LKM\srootkit\\"/
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string17 = "MODULE_NAME \"diamorphine\""
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string18 = "rmmod diamorphine"
        // Description: LKM rootkit for Linux Kernels
        // Reference: https://github.com/m0nad/Diamorphine
        $string19 = /writing\-rootkit\.txt/

    condition:
        any of them
}
