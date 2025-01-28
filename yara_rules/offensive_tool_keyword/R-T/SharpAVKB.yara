rule SharpAVKB
{
    meta:
        description = "Detection patterns for the tool 'SharpAVKB' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpAVKB"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows Antivirus Comparison and Patch Number Comparison
        // Reference: https://github.com/uknowsec/SharpAVKB
        $string1 = " --> GetWindowsAnti-VirusSoftware" nocase ascii wide
        // Description: Windows Antivirus Comparison and Patch Number Comparison
        // Reference: https://github.com/uknowsec/SharpAVKB
        $string2 = " --> GetWindowsKernelExploitsKB" nocase ascii wide
        // Description: Windows Antivirus Comparison and Patch Number Comparison
        // Reference: https://github.com/uknowsec/SharpAVKB
        $string3 = /\/SharpAVKB\.exe/ nocase ascii wide
        // Description: Windows Antivirus Comparison and Patch Number Comparison
        // Reference: https://github.com/uknowsec/SharpAVKB
        $string4 = /\/SharpAVKB\.git/ nocase ascii wide
        // Description: Windows Antivirus Comparison and Patch Number Comparison
        // Reference: https://github.com/uknowsec/SharpAVKB
        $string5 = /\\SharpAVKB\.exe/ nocase ascii wide
        // Description: Windows Antivirus Comparison and Patch Number Comparison
        // Reference: https://github.com/uknowsec/SharpAVKB
        $string6 = /\\SharpAVKB\.pdb/ nocase ascii wide
        // Description: Windows Antivirus Comparison and Patch Number Comparison
        // Reference: https://github.com/uknowsec/SharpAVKB
        $string7 = /\\SharpAVKB\-master/ nocase ascii wide
        // Description: Windows Antivirus Comparison and Patch Number Comparison
        // Reference: https://github.com/uknowsec/SharpAVKB
        $string8 = ">SharpAVKB<" nocase ascii wide
        // Description: Windows Antivirus Comparison and Patch Number Comparison
        // Reference: https://github.com/uknowsec/SharpAVKB
        $string9 = "0771a4c0fcbe55ce0e36aa1af50febcf4c2e96643a281a8de703a28f88536434" nocase ascii wide
        // Description: Windows Antivirus Comparison and Patch Number Comparison
        // Reference: https://github.com/uknowsec/SharpAVKB
        $string10 = "4bc0cedc1fa6de2b307d94dbb2bc90133a937d3fdf884a877565396e3fb0d027" nocase ascii wide
        // Description: Windows Antivirus Comparison and Patch Number Comparison
        // Reference: https://github.com/uknowsec/SharpAVKB
        $string11 = "6098d11342a5c4da204bed3fb3f420ce4df1664eb68ff23a17e4898cb3a11e07" nocase ascii wide
        // Description: Windows Antivirus Comparison and Patch Number Comparison
        // Reference: https://github.com/uknowsec/SharpAVKB
        $string12 = "99DDC600-3E6F-435E-89DF-74439FA68061" nocase ascii wide
        // Description: Windows Antivirus Comparison and Patch Number Comparison
        // Reference: https://github.com/uknowsec/SharpAVKB
        $string13 = "ed5c0c94ccd4fb0029dbfc609f8fc57580856648a188f595134f12c28ed97490" nocase ascii wide
        // Description: Windows Antivirus Comparison and Patch Number Comparison
        // Reference: https://github.com/uknowsec/SharpAVKB
        $string14 = "edd2c3b117bf18e520fc98063528a003b8958a15f731fe7646cfab0b433bf69d" nocase ascii wide
        // Description: Windows Antivirus Comparison and Patch Number Comparison
        // Reference: https://github.com/uknowsec/SharpAVKB
        $string15 = "f26f806ab5bce710cc598cc1623c2094e06b36548240c5db136d7e6d32ccbae5" nocase ascii wide
        // Description: Windows Antivirus Comparison and Patch Number Comparison
        // Reference: https://github.com/uknowsec/SharpAVKB
        $string16 = /SharpAVKB\.Cmd/ nocase ascii wide
        // Description: Windows Antivirus Comparison and Patch Number Comparison
        // Reference: https://github.com/uknowsec/SharpAVKB
        $string17 = /SharpAVKB\.exe\s\-AV/ nocase ascii wide
        // Description: Windows Antivirus Comparison and Patch Number Comparison
        // Reference: https://github.com/uknowsec/SharpAVKB
        $string18 = "uknowsec/SharpAVKB" nocase ascii wide

    condition:
        any of them
}
