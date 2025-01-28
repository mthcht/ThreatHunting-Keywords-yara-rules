rule Termite
{
    meta:
        description = "Detection patterns for the tool 'Termite' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Termite"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string1 = "/rootkiter/Binary-files" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string2 = "18c3accc4f65aae7bf7897adef35abdcca3697884860a6b5360e4f2d07bc26ed" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string3 = "3af0857c9fae7e41683d34af7e04c6ed29439466761512ebbf28bad7561d092b" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string4 = "44370c394c70f88cd9ecfb23f9d6570e2134761d1a04deea5205cec31469cfb0" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string5 = "46af7c0674c69df2af1905ea58288f24d2d10e644d5446d8d2b71b251e8e70bd" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string6 = "58fcbf640b58a45f2fed22fdd70c5d73ae781274927a2def5f71cb3e4ce02a15" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string7 = "58fcbf640b58a45f2fed22fdd70c5d73ae781274927a2def5f71cb3e4ce02a15" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string8 = "5bcac0a74645424d26b217b7725be826b7d558ecbce7ec5d3072d802e1834181" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string9 = "73fc266095e6d582b79db226145d0990129ad72c584863a61f3bd0e8056a0435" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string10 = "7aa2f4a66d72adefd632e15dee392cbeab0a843a4890598a9610660897b398f1" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string11 = "825790dbcdf9b7a69b9a566f71bc167a0a8353e735390c5815b247ac58efa817" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string12 = "8b6d83c919ad123d4b27f3404604e99eeba9196cf81f3210a65d8ae1b89465a6" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string13 = "9b3d82bb1aff3a17a490dd4da09cd315d8e94a52b8caa31ef7a7cf2a89c9d87a" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string14 = "a487628dc7647507f77cff66269d5d4588c7647e408b07ec0c4b1f16a93eefc4" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string15 = "a585eb434239e5c1714192482f20ec2483bf8eae4654ef77973524b3a151b455" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string16 = "afb55dc8b4bcff758082efde93e5ca9c2a6a725b16a4c82e7675393bf46fecfd" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string17 = "d21cccc6cb3f8313098da5b7ad6a37b5349835a702b5caf8e794a7c6903f40c5" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string18 = "d57cbbc5b6f0d223b5a3470a6a444ea4ef49dad718cbe992c92cca935cfdac7d" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string19 = "da584a49609de5985f5ba64cfb215f0c30c93fac11563ea32afa3820b3327139" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string20 = "e05ef2747f973d6ae9e4bd5fbeede55b27afd44882b83b4aee79330e856757e8" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string21 = "ef1d610dd78efae3dfa2eebade2ee76882b7e2b5df140aa068e25519d800bc63" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string22 = "ef1d610dd78efae3dfa2eebade2ee76882b7e2b5df140aa068e25519d800bc63" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string23 = /rootkiter\.com\/Termite/ nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string24 = "rootkiter/Termite" nocase ascii wide
        // Description: Termite rootit abused by threat actors
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string25 = /rootkiter\@rootkiter\.com/ nocase ascii wide
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
