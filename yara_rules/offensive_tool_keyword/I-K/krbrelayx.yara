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
        $string1 = /.{0,1000}\s\-\-dump\-adcs.{0,1000}/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string2 = /.{0,1000}\s\-\-dump\-gmsa.{0,1000}/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string3 = /.{0,1000}\s\-\-dump\-laps.{0,1000}/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string4 = /.{0,1000}\s\-\-enum\-local\-admins.{0,1000}/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string5 = /.{0,1000}\s\-f\skirbi\s.{0,1000}/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string6 = /.{0,1000}\s\-\-format\skirbi.{0,1000}/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string7 = /.{0,1000}\s\-\-krbpass\s.{0,1000}\-\-krbsalt.{0,1000}/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string8 = /.{0,1000}\/dnstool\.py.{0,1000}/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string9 = /.{0,1000}\/krbrelayx.{0,1000}/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string10 = /.{0,1000}\/printerbug\.py.{0,1000}/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string11 = /.{0,1000}addspn\.py.{0,1000}/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string12 = /.{0,1000}\-hashes.{0,1000}\s\-\-escalate\-user.{0,1000}/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string13 = /.{0,1000}krbrelayx\.git.{0,1000}/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string14 = /.{0,1000}krbrelayx\.py.{0,1000}/ nocase ascii wide
        // Description: Kerberos unconstrained delegation abuse toolkit
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string15 = /.{0,1000}krbrelayx\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
