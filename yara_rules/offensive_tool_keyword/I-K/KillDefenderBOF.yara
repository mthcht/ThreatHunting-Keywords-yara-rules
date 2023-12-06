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
        $string1 = /\/KillDefenderBOF/ nocase ascii wide
        // Description: KillDefenderBOF is a Beacon Object File PoC implementation of pwn1sher/KillDefender - kill defender
        // Reference: https://github.com/Cerbersec/KillDefenderBOF
        $string2 = /\\KillDefender\.c/ nocase ascii wide
        // Description: KillDefenderBOF is a Beacon Object File PoC implementation of pwn1sher/KillDefender - kill defender
        // Reference: https://github.com/Cerbersec/KillDefenderBOF
        $string3 = /\\KillDefender\.o/ nocase ascii wide
        // Description: KillDefenderBOF is a Beacon Object File PoC implementation of pwn1sher/KillDefender - kill defender
        // Reference: https://github.com/Cerbersec/KillDefenderBOF
        $string4 = /KillDefender\.h/ nocase ascii wide
        // Description: KillDefenderBOF is a Beacon Object File PoC implementation of pwn1sher/KillDefender - kill defender
        // Reference: https://github.com/Cerbersec/KillDefenderBOF
        $string5 = /KillDefenderBOF\-main/ nocase ascii wide
        // Description: KillDefenderBOF is a Beacon Object File PoC implementation of pwn1sher/KillDefender - kill defender
        // Reference: https://github.com/Cerbersec/KillDefenderBOF
        $string6 = /temp.{0,1000}KillDefender/ nocase ascii wide

    condition:
        any of them
}
