rule KillDefenderBOF
{
    meta:
        description = "Detection patterns for the tool 'KillDefenderBOF' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KillDefenderBOF"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: KillDefenderBOF is a Beacon Object File PoC implementation of pwn1sher/KillDefender - kill defender
        // Reference: https://github.com/Cerbersec/KillDefenderBOF
        $string1 = /.{0,1000}\/KillDefenderBOF.{0,1000}/ nocase ascii wide
        // Description: KillDefenderBOF is a Beacon Object File PoC implementation of pwn1sher/KillDefender - kill defender
        // Reference: https://github.com/Cerbersec/KillDefenderBOF
        $string2 = /.{0,1000}\\KillDefender\.c.{0,1000}/ nocase ascii wide
        // Description: KillDefenderBOF is a Beacon Object File PoC implementation of pwn1sher/KillDefender - kill defender
        // Reference: https://github.com/Cerbersec/KillDefenderBOF
        $string3 = /.{0,1000}\\KillDefender\.o.{0,1000}/ nocase ascii wide
        // Description: KillDefenderBOF is a Beacon Object File PoC implementation of pwn1sher/KillDefender - kill defender
        // Reference: https://github.com/Cerbersec/KillDefenderBOF
        $string4 = /.{0,1000}KillDefender\.h.{0,1000}/ nocase ascii wide
        // Description: KillDefenderBOF is a Beacon Object File PoC implementation of pwn1sher/KillDefender - kill defender
        // Reference: https://github.com/Cerbersec/KillDefenderBOF
        $string5 = /.{0,1000}KillDefenderBOF\-main.{0,1000}/ nocase ascii wide
        // Description: KillDefenderBOF is a Beacon Object File PoC implementation of pwn1sher/KillDefender - kill defender
        // Reference: https://github.com/Cerbersec/KillDefenderBOF
        $string6 = /.{0,1000}temp.{0,1000}KillDefender.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
