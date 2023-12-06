rule AttackSurfaceMapper
{
    meta:
        description = "Detection patterns for the tool 'AttackSurfaceMapper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AttackSurfaceMapper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string1 = /\sasm\.py\s\-t\s.{0,1000}\s\-ln\s\-w\sresources\/.{0,1000}\.txt\s\-o\s/ nocase ascii wide
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string2 = /\/AttackSurfaceMapper\.git/ nocase ascii wide
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string3 = /\/email_spoof_checks\.txt/ nocase ascii wide
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string4 = /\/guessed_emails\.txt/ nocase ascii wide
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string5 = /AttackSurfaceMapper\-master/ nocase ascii wide
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string6 = /bitquark_top100k_sublist\.txt/ nocase ascii wide
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string7 = /commonspeak_sublist\.txt/ nocase ascii wide
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string8 = /superhedgy\/AttackSurfaceMapper/ nocase ascii wide
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string9 = /top100_sublist\.txt/ nocase ascii wide
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string10 = /top1000_sublist\.txt/ nocase ascii wide

    condition:
        any of them
}
