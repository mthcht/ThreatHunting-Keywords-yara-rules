rule ForkPlayground
{
    meta:
        description = "Detection patterns for the tool 'ForkPlayground' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ForkPlayground"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string1 = /\sForkDump\.cpp/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string2 = /\sForkLib\.cpp/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string3 = /\/ForkDump\.cpp/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string4 = /\/ForkLib\.cpp/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string5 = /\/ForkPlayground\.git/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string6 = /\\ForkDump\.cpp/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string7 = /\\ForkDump\.exe/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string8 = /\\ForkDump\.vcxproj/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string9 = /\\ForkLib\.cpp/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string10 = /\\ForkLib\.vcxproj/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string11 = /\\ForkPlayground\.sln/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string12 = /18C681A2\-072F\-49D5\-9DE6\-74C979EAE08B/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string13 = /AD495F95\-007A\-4DC1\-9481\-0689CA0547D9/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string14 = /D4stiny\/ForkPlayground/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string15 = /ForkDump\-x64\.exe/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string16 = /ForkDump\-x64\.pdb/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string17 = /ForkDump\-x86\.exe/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string18 = /ForkDump\-x86\.pdb/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string19 = /ForkPlayground\-master/ nocase ascii wide

    condition:
        any of them
}
