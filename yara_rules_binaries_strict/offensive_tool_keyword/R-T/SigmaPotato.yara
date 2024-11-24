rule SigmaPotato
{
    meta:
        description = "Detection patterns for the tool 'SigmaPotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SigmaPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string1 = " --revshell" nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string2 = /\/SigmaPotato\.git/ nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string3 = "/SigmaPotato/releases/download/" nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string4 = /\\\\pipe\\\\SigmaPotato/ nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string5 = /\\pipe\\SigmaPotato/ nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string6 = /\\SigmaPotato\.csproj/ nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string7 = "148b284dead436f9dbbc23f7e4861901ddc7f1d2cc03c49b8b0379ff6b5633b4" nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string8 = "14a0ceba63b3d76d7d30653112a0b43e3a2ef1f07a8030d7a949696b5c3065f6" nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string9 = "2AE886C3-3272-40BE-8D3C-EBAEDE9E61E1" nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string10 = "351b7ea09ad99959f21e0c21bef93112ec360ccef4bc0cbaaed390a16631326b" nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string11 = "37ee54a15c44f222327a9d77243113c2b0efb07451eca2f887d314b6e0963f86" nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string12 = "4de639c973c8f91cf5e4e9c8078dacbbec2de8443b400c8233f1b5dae48a9444" nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string13 = "6a2c34b319067eea1310e221cff99ce5150be0a82a822fb280554974f6d60dd2" nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string14 = "876236cb7297de4232a08d57ff6e5929ad522d150f35a288915f9e0a1d4b9968" nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string15 = "93052e4a139b6f66aed0be356b47c2816bf121445df85ca5369d024fc06c6f5f" nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string16 = "a7a1bc83f94696c2ef637e12c28afd5f5cbb8f7d0cf22cb41921d77b6c39a721" nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string17 = "bcaea27cde09d870a66d227e61d4be463e0d943831c8728612489b0587e34676" nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string18 = "e17d9c10a343762b54f938c0eaf63f479140792c7a27c876d4bccfe09e5d924c" nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string19 = "ec68a6bf7f104a815bd21e27e73a8dfb8afcb282d4997bebe9eccd6c89259506" nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string20 = "ed0baea4cf8c5e3a0dce2db731ab38e324ce9db4269952fd9b90dc007c5d4291" nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string21 = "f54c0294b0a07f49dc21ec7978c25cc5e75947646832675f1af782384aee911f" nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string22 = "Invoke-SigmaPotato " nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string23 = /Invoke\-SigmaPotato\.ps1/ nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string24 = "ncacn_ip_tcp:fuck you !" nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string25 = /powershell\s\-e\s\$env\:SigmaBootstrap/ nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string26 = /SigmaPotato\.exe/ nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string27 = /SigmaPotatoCore\.exe/ nocase ascii wide
        // Description: SeImpersonate privilege escalation tool
        // Reference: https://github.com/tylerdotrar/SigmaPotato
        $string28 = "tylerdotrar/SigmaPotato" nocase ascii wide
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
