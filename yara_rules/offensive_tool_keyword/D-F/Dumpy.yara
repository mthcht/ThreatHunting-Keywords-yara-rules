rule Dumpy
{
    meta:
        description = "Detection patterns for the tool 'Dumpy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dumpy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Reuse open handles to dynamically dump LSASS
        // Reference: https://github.com/Kudaes/Dumpy
        $string1 = /\.exe\s\-\-dump\s\-k\s.{0,1000}\s\-u\shttp/ nocase ascii wide
        // Description: Reuse open handles to dynamically dump LSASS
        // Reference: https://github.com/Kudaes/Dumpy
        $string2 = /\/dumpy\.exe/ nocase ascii wide
        // Description: Reuse open handles to dynamically dump LSASS
        // Reference: https://github.com/Kudaes/Dumpy
        $string3 = /\/Dumpy\.git/ nocase ascii wide
        // Description: Reuse open handles to dynamically dump LSASS
        // Reference: https://github.com/Kudaes/Dumpy
        $string4 = /\[\!\]\sLsass\sdump\screated\!/ nocase ascii wide
        // Description: Reuse open handles to dynamically dump LSASS
        // Reference: https://github.com/Kudaes/Dumpy
        $string5 = /\[\+\]\sSuccessfully\sdecrypted\sminidump\sfile/ nocase ascii wide
        // Description: Reuse open handles to dynamically dump LSASS
        // Reference: https://github.com/Kudaes/Dumpy
        $string6 = /\\dumpy\.exe/ nocase ascii wide
        // Description: Reuse open handles to dynamically dump LSASS
        // Reference: https://github.com/Kudaes/Dumpy
        $string7 = "7876ba8fb2f4a1e4802f1f2c1030b9bc708f3981264fea33e261be7e05966169" nocase ascii wide
        // Description: Reuse open handles to dynamically dump LSASS
        // Reference: https://github.com/Kudaes/Dumpy
        $string8 = /dumpy\.exe\s\-\-dump/ nocase ascii wide
        // Description: Reuse open handles to dynamically dump LSASS
        // Reference: https://github.com/Kudaes/Dumpy
        $string9 = "Kudaes/Dumpy" nocase ascii wide

    condition:
        any of them
}
