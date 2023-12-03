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
        $string1 = /.{0,1000}\sasm\.py\s\-t\s.{0,1000}\s\-ln\s\-w\sresources\/.{0,1000}\.txt\s\-o\s.{0,1000}/ nocase ascii wide
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string2 = /.{0,1000}\/AttackSurfaceMapper\.git.{0,1000}/ nocase ascii wide
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string3 = /.{0,1000}\/email_spoof_checks\.txt.{0,1000}/ nocase ascii wide
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string4 = /.{0,1000}\/guessed_emails\.txt.{0,1000}/ nocase ascii wide
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string5 = /.{0,1000}AttackSurfaceMapper\-master.{0,1000}/ nocase ascii wide
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string6 = /.{0,1000}bitquark_top100k_sublist\.txt.{0,1000}/ nocase ascii wide
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string7 = /.{0,1000}commonspeak_sublist\.txt.{0,1000}/ nocase ascii wide
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string8 = /.{0,1000}superhedgy\/AttackSurfaceMapper.{0,1000}/ nocase ascii wide
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string9 = /.{0,1000}top100_sublist\.txt.{0,1000}/ nocase ascii wide
        // Description: AttackSurfaceMapper (ASM) is a reconnaissance tool that uses a mixture of open source intelligence and active techniques to expand the attack surface of your target
        // Reference: https://github.com/superhedgy/AttackSurfaceMapper
        $string10 = /.{0,1000}top1000_sublist\.txt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
