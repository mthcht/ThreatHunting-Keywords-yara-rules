rule krbrelayx
{
    meta:
        description = "Detection patterns for the tool 'krbrelayx' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "krbrelayx"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string1 = /\s\-\-dump\-adcs/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string2 = /\s\-\-dump\-gmsa/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string3 = /\s\-\-dump\-laps/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string4 = /\s\-\-enum\-local\-admins/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string5 = /\s\-f\skirbi\s/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string6 = /\s\-\-format\skirbi/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string7 = /\s\-\-krbpass\s.{0,1000}\-\-krbsalt/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string8 = /\/dnstool\.py/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string9 = /\/krbrelayx/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string10 = /\/printerbug\.py/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string11 = /addspn\.py/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string12 = /\-hashes.{0,1000}\s\-\-escalate\-user/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string13 = /krbrelayx\.git/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string14 = /krbrelayx\.py/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string15 = /krbrelayx\-master/ nocase ascii wide

    condition:
        any of them
}
