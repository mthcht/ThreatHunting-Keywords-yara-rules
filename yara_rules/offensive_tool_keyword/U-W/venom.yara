rule Venom
{
    meta:
        description = "Detection patterns for the tool 'Venom' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Venom"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string1 = /\sport_reuse\.py/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string2 = /\s\-\-string\s\'venomcoming\'\s/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string3 = /\s\-\-string\s\'venomleaving\'\s/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string4 = /\/port_reuse\.py/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string5 = /\/Venom\.git/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string6 = /\/Venom\.v1\.0\.1\.7z/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string7 = /\/Venom\.v1\.0\.2\.7z/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string8 = /\/Venom\.v1\.0\.7z/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string9 = /\/Venom\.v1\.1\.0\.7z/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string10 = /\/Venom\/tarball\/v/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string11 = /\/Venom\/zipball\/v/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string12 = /\\port_reuse\.py/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string13 = /\\Venom\.v1\.0\.1\.7z/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string14 = /\\Venom\.v1\.0\.2\.7z/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string15 = /\\Venom\.v1\.0\.7z/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string16 = /\\Venom\.v1\.1\.0\.7z/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string17 = /37da8267b295caeca8fadb13206ba1c498a7012673430c5d856fe93862446a28/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string18 = /52907aebc7d2c6534099d149e61bf294b0ddf7d4e814a72b3621e3a829f83c97/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string19 = /admin_macos_x64\s\-rhost\s.{0,1000}\s\-rport\s/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string20 = /agent\.exe\s\-lhost\s.{0,1000}\s\-reuse\-port\s/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string21 = /agent_linux_x64\s\-lport\s/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string22 = /agent_linux_x64\s\-rhost\s.{0,1000}\s\-rport\s/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string23 = /Venom\sAdmin\sNode\sStart/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string24 = /Venom\\agent\\agent\.go/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string25 = /You\scan\sexecute\scommands\sin\sthis\sshell\s\:D/ nocase ascii wide

    condition:
        any of them
}
