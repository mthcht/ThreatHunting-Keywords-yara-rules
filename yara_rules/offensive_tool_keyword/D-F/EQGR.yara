rule EQGR
{
    meta:
        description = "Detection patterns for the tool 'EQGR' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EQGR"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Equation Group hack tool leaked by ShadowBrokers- file elgingamble Local exploit for the public prctl core dump vulnerability in recent Linux kernels
        // Reference: https://fdik.org/EQGRP/Linux/doc/old/etc/user.tool.elgingamble.COMMON
        $string1 = /.{0,1000}\[\-\]\sfailed\sto\sspawn\sshell:\s\%s.{0,1000}/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file elgingamble Local exploit for the public prctl core dump vulnerability in recent Linux kernels.
        // Reference: https://fdik.org/EQGRP/Linux/doc/old/etc/user.tool.elgingamble.COMMON
        $string2 = /.{0,1000}\[\-\]\skernel\snot\svulnerable.{0,1000}/ nocase ascii wide
        // Description: Equation Group scripts and tools
        // Reference: https://fdik.org/EQGRP/Linux/doc/old/etc/abopscript.txt
        $string3 = /.{0,1000}abopscript\.txt.{0,1000}/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file elgingamble
        // Reference: https://fdik.org/EQGRP/Linux/doc/old/etc/user.tool.elgingamble.COMMON
        $string4 = /.{0,1000}chown\sroot\s\%s\s\schmod\s4755\s\%s\s\s\%s.{0,1000}/ nocase ascii wide
        // Description: Equation Group scripts and tools
        // Reference: https://fdik.org/EQGRP/Linux/doc/old/etc/abopscript.txt
        $string5 = /.{0,1000}cp\s\/etc\/shadow\s\/tmp\/\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
