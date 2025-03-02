rule Carbanak
{
    meta:
        description = "Detection patterns for the tool 'Carbanak' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Carbanak"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string1 = /\\\\\\\\\.\\\\pipe\\\\\\"\sMIMIKATZ/ nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string2 = /\\pipe\\MIMIKATZ/ nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string3 = /\\server\\VncSharp\\obj\\Debug\\VncSharp\.pdb/ nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string4 = "0037e201d072aabd5bf4f22b6c9eb7f780d5007616dd130e8ffcdbd8d491c509" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string5 = "01871B2B-B006-4069-997D-BAB3EB216160" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string6 = "0845B3E9-B6AE-4227-B484-CECBC2EB1C87" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string7 = "0acf29e9ae705e5518a55e9020f69e9bdc9348d6374d054720b6169cfdc5ca87" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string8 = "0d3f1696aae8472145400d6858b1c44ba7532362be5850dae2edbd4a40f36aa5" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string9 = "120edd37142c24d17472137c608220220a4efb595d42a991efd498ac30339b4e" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string10 = "1B454840-E496-4F27-AA18-439A4E97BCC6" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string11 = "29390239-C06E-4F26-B5A3-594A08D8D30C" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string12 = "2F8E74D2-3474-408C-9469-A4E3C97B7BBF" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string13 = "315C301F-E392-4F7D-9108-8E621C11D662" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string14 = "39b545c7cd26258a9e45923053a5a64c9461470c3d7bfce3be1c776b287e8a95" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string15 = "3bf8610241a808e85e6ebaac2bb92ba4ae92c3ec1a6e56e21937efec71ea5425" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string16 = "3C0E89F1-1D3D-4651-9A44-FCCABB340E02" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string17 = "40ce820df679b59476f5d277350dca43e3b3f8cac7ec47ad638371aaa646c315" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string18 = "41955340b55ee3c2054263a008c141151db9fcc0816b08905771e26e3739f411" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string19 = "487B9D03-F5C6-45D5-A159-3148F98B5179" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string20 = "54be339f0e1263b36efc2eae53780ea14e098f94fb2fbe0f6df4f7b2dafb8ce9" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string21 = "55341dfe5a2e7ff47bde6573885693ec67d9662c40a7b321059fe1af6d5babaf" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string22 = "606da919a03a92204bcd8653dfad8ebd79bc1a05b4760ce92c0d85eb2dc0439d" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string23 = "6EFFA73B-AB71-4594-AEFF-1C127387A9CE" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string24 = "74da983c63f4c77eafcd9953c0705f01e2dfcc30a14fded06ff1e2641b8ea856" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string25 = "8169F27E-0314-44BB-8B89-DB3339FF51A3" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string26 = "822d1259e7b03a5113743e2840d3338236159670d94aaf41431b7d6391268300" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string27 = "827D241C-6A9B-48B0-BA8C-F21EF2849405" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string28 = "886C26DC-0073-4BB7-823B-2B9DAD53DB8B" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string29 = "901E099B-A01A-4F21-9A6F-8D3B60F04168" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string30 = "94c1bf751c218c05c084d309a18c98a54385abc6b41b03b456ef0747e5abd8e9" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string31 = "989A9793-63FC-4639-8A8D-E4BB9F60F137" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string32 = "AB850676-3744-4BFD-82FA-E21D19622BF9" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string33 = "ACEE9097-0CA8-4520-A6CA-3BF97B7A86DE" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string34 = "B2D22DC6-1CA5-4CE3-9756-3673336705FB" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string35 = "d10af443de7fe12f8aa50bc39d5e86d25ff8b789bf8763a61f9f84cf97bd0f53" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string36 = "d470da028679ca8038b062f9f629d89a994c79d1afc4862104611bb36326d0c8" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string37 = "db486e0cb94cf2bbe38173b7ce0eb02731ad9a435a04899a03d57b06cecddc4d" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string38 = "E0695F0F-0FAF-44BC-AE55-A1FCBFE70271" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string39 = "e5ee043da6e74b1cbee3fd4035a6f80a22c89e1813c5bfbd2572a594f93fd740" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string40 = "e7d89d1f23c2c31e2cd188042436ce6d83dac571a5f30e76cbbcdfaf51e30ad9" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string41 = "ecf3679f659c5a1393b4a8b7d7cca615c33c21ab525952f8417c2a828697116a" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string42 = "F2D38A31-CF17-4962-A601-6779F18FDBF2" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string43 = "F34C5DF4-22A6-49CF-901E-D6DD338061F1" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string44 = "FC8F9DFC-3A81-4427-BFE5-DA11572EA8B5" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string45 = "fdc0ec0cc895f5b0440d942c0ab60eedeb6e6dca64a93cecb6f1685c0a7b99ae" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string46 = "FE66CDDF-8E33-4153-81AF-24BE392698D8" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string47 = "IE/Edge Grabber Begin" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string48 = "kuhl_m_sekurlsa_msv_pth_makefakestring" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string49 = /mimikatz\.log/ nocase ascii wide
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
