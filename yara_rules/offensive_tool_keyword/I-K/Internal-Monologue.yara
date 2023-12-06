rule Internal_Monologue
{
    meta:
        description = "Detection patterns for the tool 'Internal-Monologue' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Internal-Monologue"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS
        // Reference: https://github.com/eladshamir/Internal-Monologue
        $string1 = /\s\-Downgrade\sFalse\s\-Restore\sFalse\s\-Impersonate\sTrue\s.{0,1000}\s\-challange\s/ nocase ascii wide
        // Description: Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS
        // Reference: https://github.com/eladshamir/Internal-Monologue
        $string2 = /Internal\-Monologue\.exe/ nocase ascii wide
        // Description: Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS
        // Reference: https://github.com/eladshamir/Internal-Monologue
        $string3 = /InternalMonologueDll/ nocase ascii wide
        // Description: Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS
        // Reference: https://github.com/eladshamir/Internal-Monologue
        $string4 = /InternalMonologueExe/ nocase ascii wide

    condition:
        any of them
}
