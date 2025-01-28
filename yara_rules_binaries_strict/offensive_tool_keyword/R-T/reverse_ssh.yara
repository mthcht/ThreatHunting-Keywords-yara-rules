rule reverse_ssh
{
    meta:
        description = "Detection patterns for the tool 'reverse-ssh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reverse-ssh"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string1 = /\sid_reverse\-ssh\.pub/ nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string2 = /\.\/reverse\-ssh/
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string3 = /\/id_reverse\-ssh\.pub/ nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string4 = /\/reverse\-ssh\.git/ nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string5 = "/reverse-ssh/"
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string6 = "/reverse-ssh-armv7-x86" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string7 = "/reverse-ssh-armv8-x64" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string8 = "/reverse-sshx64" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string9 = /\\reverse\-ssh\\/ nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string10 = "031c6896d87b890a2cd54948297d5d804a5e3b52a067a81b7dd12c1c4ad77496" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string11 = "06f02a7b690087feea7f4e48b71e219c98de681cf3b1fdc3097f6264775dab62" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string12 = "11055d6a12b8735ded0fe5289323c15cd237caa413c0aca76951b3b3a4178806" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string13 = "12e0ec8e9b714f9f157496dace0e714238403b5e8f3000bbeedf31b0a811bf73" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string14 = "161fd76c83e557269bee39a57baa2ccbbac679f59d9adff1e1b73b0f4bb277a6" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string15 = "18cc8188bbdd5cfa13840e0cd62c447979d860cd6366c5abe17be70ff4be5a24" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string16 = "1920ded3be0d3f44df039d4ccd7597ecdc62d7b994364ad25f3021e5c9428731" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string17 = "19dc8d8108bab9207905b08b57193efc9fd4e13f2cb901c7ca1ffd727cd62e4a" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string18 = "1aec829442fb9d5d32cb59019f608c9e98af9ebff8b56168f38ac5e222c888ba" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string19 = "1b5b1dcea5728489f0373d6f8f351d69912498c61829ceccf5c5d0233bf0c852" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string20 = "1b789e0e641506e259b2e4e2a64dac2654f224dcaf4d57da0634ce4774eb9b90" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string21 = "1db6bf67e6e3a421c4cd377cdd026a5de25a55809a9a2c56e0aa092ef4c8e02e" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string22 = "3112a8da28bf74a57ed30ef6ee827f6f832e3053db1ec04fc0f465b6e0c2f2d0" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string23 = "3560411a4c3ed8e9229e7684be1c002f39cdaa5482c6d5046984d4be7985a594" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string24 = "38074409fb6889d1a58cbda706a1167410e4a640630cf128472902a5967074af" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string25 = "43da5889dce96d8f11dd09ab509217c13aad4a9cc51538633428aa9887b1039d" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string26 = "470150f91aebe1fd59949728f99b2bb847cf8d1867ca2ee767fef9b7c44e206d" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string27 = "4b591b30acc45d581d7500bd107dea8155d325d3d8147d9cd4bd6c6aa3db7a98" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string28 = "4d5886e86e0a2c97e72a648d63ba392c9ac14c8a973b454c11ecd223e2ccc9cc" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string29 = "559e5ff2b8afb25bbc62275355ba2ceb668e8707de6b221315afb6c2390ba68e" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string30 = "5900fc96f25ad0d41cbed1bb7b0f38bde26e0ebebc290f1a294ffedeb1d68b83" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string31 = "59aa09cb628399ea3c2a900cb391238cea0bbe9083868f9fcfa4c13dcbf0b702" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string32 = "5b1ce3529f7881a1252086a73bdbb45d6e9debb50f92b9c42fad341e34146437" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string33 = "72ca2211283a4596dbd2881e3cbd8fb8f07420e0b7404bb298eab30873f487ed" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string34 = "7cc2ba97a45b159405891baba5ac216334e89d878a4efcdf47492c284cc6342e" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string35 = "84f191e9992ba2fd44147adea679f3315d3bc3a21d3c3267425017711a240da7" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string36 = "862a3fb241e9b9e821a5612e1dd5f7565aefdaee978bef994bc4817d9711409d" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string37 = "8b41d9f80065f1bdcef489969e314c71f6f36265f6b6b5250a90608b9f393cdb" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string38 = "927c3728901bdfa38cd1ec9e7ca972923b1cc51d7159e0d25e2c063e6d2a2f60" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string39 = "9399f2fe7c63989641f911a519930e9139ff4987c0bdaee56c25d68c4c64a63b" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string40 = "AAAADkl0J3MgbWUgYnJ1ZGkhAQIDBAUGBw==" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string41 = "ad042ec9afbf29b4b962820a1e82f4d1d6a8c654c42f3c55d6e562dc7a279766" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string42 = "d5ad2fca7e56448f82eb0da69d8578abf2acce9616d9849622ccd17655f73285" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string43 = "da130b91b87ce2cc4e21f221d51f2ee1d9a3052a1d414b7028a78ebf2fd8168c" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string44 = "dadc9d874254d500356528ea6bfedbe9f8db453c4d64e2dfd7d68f97cd0f973d" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string45 = "db2b4e0e013a0302f6ebe82935a1e416b6672dd447030c194c638585525c3354" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string46 = "dc1baea53709f425ba181705c3f6c37d4840e3e88d71a5e3b39ee40948f12e87" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string47 = "dcd89774d490ecfe91a08d0dcfc37065965f31aab2593987839f5afa19625a36" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string48 = "df022228501cd23496cd0e6c761d31ccb8b754032f27e2c78a8b1447bc8f512f" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string49 = "e54299149f25b882cb0900a2977eb6d72a4fa88fb96b67b370981b42b66d7733" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string50 = "ebc544aa7679a2d04acf28f4df70bdfe827962993447321ca71e408dd4e10414" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string51 = "f4c56a0ddc1228394dd2a4dd30746644af6a25e5071cb28db71cb1c8c248bef6" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string52 = "Fahrj/reverse-ssh" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string53 = "fd9af8832336604029ef8f8ce6c35f5b24efdcd593b5092ed4774dae62d8e9f8" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string54 = "letmeinbrudipls" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string55 = /reverse\-ssh\s.{0,100}\@/ nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string56 = "reverse-ssh -p" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string57 = "reverse-ssh -v" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string58 = /reverse\-ssh\.exe/ nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string59 = "reverse-ssh/releases/latest" nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string60 = /reverse\-sshx64\.exe/ nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string61 = /reverse\-sshx86\.exe/ nocase ascii wide
        // Description: Statically-linked ssh server with reverse shell functionality for CTFs and such
        // Reference: https://github.com/Fahrj/reverse-ssh
        $string62 = /ssh\-shellhost\.exe/ nocase ascii wide
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
