rule r77_rootkit
{
    meta:
        description = "Detection patterns for the tool 'r77-rootkit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "r77-rootkit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string1 = /\sr77\-x64\.dll/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string2 = /\sr77\-x86\.dll/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string3 = /\/r77\-rootkit\.git/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string4 = /\/r77\-x64\.dll/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string5 = /\/r77\-x86\.dll/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string6 = /\\\.\\pipe\\\$77childproc/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string7 = /\\\.\\pipe\\\$77childproc64/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string8 = /\\\.\\pipe\\\$77control_redirect/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string9 = /\\\\\.\\\\pipe\\\\\$77childproc/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string10 = /\\\\\.\\\\pipe\\\\\$77control_redirect/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string11 = /\\\\\\\\\.\\\\pipe\\\\\$77childproc64/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string12 = /\\\\pipe\\\\\$77control/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string13 = /\\InstallShellcode\.exe/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string14 = /\\pipe\\\$77control/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string15 = /\\r77config\.c/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string16 = /\\r77\-rootkit\\/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string17 = /\\r77\-x64\.dll/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string18 = /\\r77\-x86\.dll/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string19 = /00D7268A\-92A9\-4CD4\-ADDF\-175E9BF16AE0/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string20 = /06AF1D64\-F2FC\-4767\-8794\-7313C7BB0A40/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string21 = /1BA54A13\-B390\-47B3\-9628\-B58A2BBA193B/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string22 = /2D6FDD44\-39B1\-4FF8\-8AE0\-60A6B0979F5F/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string23 = /4D71336E\-6EF6\-4DF1\-8457\-B94DC3D73FE7/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string24 = /7271AFD1\-10F6\-4589\-95B7\-3ABF98E7B2CA/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string25 = /78BB6D02\-6E02\-4933\-89DC\-4AD8EE0B303F/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string26 = /86F8C733\-F773\-4AD8\-9282\-3F99953261FD/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string27 = /addc2b1c765eb8512c2fc911e2f7dca94a51a88048ae3e2ef51b74fe955e61bc/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string28 = /AFB848D0\-68F8\-42D1\-A1C8\-99DFBE034FCF/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string29 = /BCE48DAE\-232E\-4B3D\-B5B5\-D0B29BB7E9DE/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string30 = /bytecode77\/r77\-rootkit/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string31 = /E3104B33\-DB3D\-4C83\-B393\-1E05E1FF2B10/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string32 = /E55F7214\-8CC4\-4E1D\-AEDB\-C908D23902A4/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string33 = /F0005D08\-6278\-4BFE\-B492\-F86CCEC797D5/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string34 = /r77Rootkit\%201\.5\.2\.zip/ nocase ascii wide
        // Description: Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // Reference: https://github.com/bytecode77/r77-rootkit
        $string35 = /SOFTWARE\\\$77config/ nocase ascii wide

    condition:
        any of them
}
