rule resocks
{
    meta:
        description = "Detection patterns for the tool 'resocks' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "resocks"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string1 = /\$RESOCKS_KEY/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string2 = /\/resocks\s.{0,100}\s\-\-key\s/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string3 = /\/resocks\.git/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string4 = /\/resocks\/releases\/latest/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string5 = /\/resocks_.{0,100}_Linux_x86_64\.tar\.gz/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string6 = /\/resocks_.{0,100}_macOS_arm64\.tar\.gz/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string7 = /\/resocks_Darwin_x86_64\.tar\.gz/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string8 = /\/resocks_Linux_.{0,100}\.tar\.gz/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string9 = /0bd2acc669f0084786cd7df668e279e21e71556e9e927235a54f8bc6c1a27fa7/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string10 = /29eb65e949707d372888fa09a691afd2d186e9ca6d97a5a7e89867468b675760/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string11 = /2edd8774c18c9ba021f29ea142729d82bacf37ef2c58b45f43a7507785670c53/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string12 = /358f4605b34480a8bc335e7ba588171d12a7c14c7219b2438c3594392b7c0468/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string13 = /3c9fdaf1fc583a55cb67fbbd267e295773495cfb3e18dd0b6dfe4db8e9d82a44/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string14 = /4a9652d48155a187a4c87e8d243f3b2514879927e9b8d56bd17e9b1c0d50da4b/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string15 = /784f96fcd55e4e19e9178acc0b38fbb1536821a8ffdbf02a1606eec74ef82d4f/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string16 = /8ef32f05998a4cc84237167458d42df34b3dc8534fb823ba909a8b2f76977eb7/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string17 = /95ae5c9ab4faf301a44b0c4c0d98d88fd12191667b0f8c78cf933b32df3ff577/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string18 = /a080c293df2577cc210e889abb0be13126606f159ff4b2c88323dc753f7b2c2c/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string19 = /a352a6b52e5433a2dc19445287db1537ae6385dc6e1b2b11f53c222b14aae75d/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string20 = /a992acc4b4e48dd6cdc389dcaf2291b330854f0b17369b1429590d3f824c3dfe/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string21 = /abb8b93592a482b653c6d282ccad216f6cedc8bb50476aada7ee4b3562ecc9a4/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string22 = /bc511e38827372f9bbfcd48fd448c51c0051f7cb64a91b2b4d0208a4dade3d22/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string23 = /c9e4ebc73927d640543ab65574a94eed4d072e59d366ab37be405605914fa42d/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string24 = /Connect\sback\sto\san\s.{0,100}\slistener\sand\srelay\sthe\sSOCKS5\straffic/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string25 = /d18597195b9b81b9e401547e4b630acf09ad39401bdcc8b5fa2e05e4677cf46f/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string26 = /d2ea7a48b45df38e486ffe3757119d2257cd4b2a560ca67c463aff63e9a34a0d/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string27 = /export\sRESOCKS_KEY\=/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string28 = /f108ce909b11c42406540ae67c339f22fd9842db9ecdc5765bcd2b35f5723198/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string29 = /RedTeamPentesting\/kbtls/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string30 = /RedTeamPentesting\/resocks/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string31 = /resocks\sgenerate/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string32 = /resocks\slisten/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string33 = /resocks\/proxyrelay/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string34 = /resocks_Windows_x86_64\.zip/ nocase ascii wide
        // Description: resocks is a reverse/back-connect SOCKS5 proxy tunnel that can be used to route traffic through a system that can't be directly accessed
        // Reference: https://github.com/RedTeamPentesting/resocks
        $string35 = /SOCKS5\sserver\sactive/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
