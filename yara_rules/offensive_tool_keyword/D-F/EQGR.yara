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
        $string1 = /\[\-\]\sfailed\sto\sspawn\sshell\:\s\%s/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file elgingamble Local exploit for the public prctl core dump vulnerability in recent Linux kernels.
        // Reference: https://fdik.org/EQGRP/Linux/doc/old/etc/user.tool.elgingamble.COMMON
        $string2 = /\[\-\]\skernel\snot\svulnerable/ nocase ascii wide
        // Description: Equation Group scripts and tools
        // Reference: https://fdik.org/EQGRP/Linux/doc/old/etc/abopscript.txt
        $string3 = /abopscript\.txt/ nocase ascii wide
        // Description: Equation Group hack tool leaked by ShadowBrokers- file elgingamble
        // Reference: https://fdik.org/EQGRP/Linux/doc/old/etc/user.tool.elgingamble.COMMON
        $string4 = /chown\sroot\s\%s\s\schmod\s4755\s\%s\s\s\%s/ nocase ascii wide
        // Description: Equation Group scripts and tools
        // Reference: https://fdik.org/EQGRP/Linux/doc/old/etc/abopscript.txt
        $string5 = /cp\s\/etc\/shadow\s\/tmp\/\./ nocase ascii wide

    condition:
        any of them
}
