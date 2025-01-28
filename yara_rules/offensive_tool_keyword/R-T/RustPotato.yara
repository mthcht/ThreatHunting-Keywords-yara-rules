rule RustPotato
{
    meta:
        description = "Detection patterns for the tool 'RustPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RustPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string1 = " -p 4444 -c powershell" nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string2 = "/pipe/RustPotato" nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string3 = /\/RustPotato\.git/ nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string4 = /\[\-\]\sFailed\sto\sstart\sreverse\sshell/ nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string5 = /\\\\pipe\\\\RustPotato/ nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string6 = /\\pipe\\RustPotato/ nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string7 = /\\RustPotato\-main/ nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string8 = "emdnaia/RustPotato" nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string9 = "f458f32e49cf7c57bd3bd32e9c82217f2faab412155c9e2a7c28d1b1b4848c42" nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string10 = "localhost/pipe/RustPotato" nocase ascii wide
        // Description: A Rust implementation of GodPotato - abusing SeImpersonate to gain SYSTEM privileges
        // Reference: https://github.com/emdnaia/RustPotato
        $string11 = /RustPotato\.exe/ nocase ascii wide

    condition:
        any of them
}
