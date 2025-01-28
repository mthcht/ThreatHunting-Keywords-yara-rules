rule Carseat
{
    meta:
        description = "Detection patterns for the tool 'Carseat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Carseat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string1 = /\sCarSeat\.py\s/ nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string2 = /\/Carseat\.git/ nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string3 = /\/CarSeat\.py\s\-/ nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string4 = "09b0fe289efa8c6364964bddedb339a7d43b0eaae912ef4c3f357325c6c55b61" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string5 = "0aa81384c29ae395069a9d6bf226f1345c7909cdc7181c2c4f1c9015268e940d" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string6 = "0xthirteen/Carseat" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string7 = "15a2171b1424a78028131808a24d39d5f5383cfd4540ea360a74f9b7c752933d" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string8 = "1ae56e7ebbdbbd3912b3bec2f08c065895e82492494c26d076cce466dd0572ad" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string9 = "1ea81f89cfaaf2fe3273f042bb4eaafc1046fbc3ceb146b79eee8a898a189b45" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string10 = "2236b69f5c5c266ca57af9f9a2fddd35a36b4dd4de5ee279f87d2bf2e769bc81" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string11 = "28f3463d7e6c3c5cc339f624712cee8e8277fffc2c6a4bf356cd4cb59ab4efce" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string12 = "2e7780d7593f341c0b72ad38f91638cfbb917e7f9f342b3ffaa842d207d4ab85" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string13 = "3002cc4ccf57741919e563283d63b762f29512aafe16837b297c6d70e014bd04" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string14 = "34b57458547e8ecd072caffdd5f390098197f2bef7cee067b0122b2c153f4b01" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string15 = "35c64b018248a12e677777eab956c086212a2fe5d7206e76d66ac5dc9fa41103" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string16 = "36a51b581592148e33c4f47c4e4f72710564595b6147b732e203d27a6d7dabb5" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string17 = "39832c87758a620ccc75fcbdacee79993652fd81597ce79f52bab3f4b9abd2a5" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string18 = "3c9f2deb4c664d6321474815f4fefa2c80778fe2da2a9a35d1a31f2f9106bf96" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string19 = "417f92b83d18cb5d231496fde3d743a34d2f483c26cf831742e30cc11c3963bb" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string20 = "41fe9889b428813cda89d017204555e013cf5c081122cd821f6c343ccc2ffcb7" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string21 = "4374b7f67ac23d9fc63fac8b9da7e279edd897ee5854d6a67c64ec648974e3fa" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string22 = "49c9788a669f864351f347d5f13e34cab961a6bc88afe5f8a5e32e868a2fc81d" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string23 = "4a852249475372d387ac1ba1c5ccd8b541dac4d89fb4ec51877cad81024a0c08" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string24 = "4b6df010ff6834f9d493d178079730ebd03f3fefd7a1e8da6c4456f2ed8d6296" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string25 = "4c230850f0fab974effc07d9ac7df6d11f2d49cac19d71da269d1c1d18e574e2" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string26 = "50c461593a4ad6f09903a04e528de6991e745be1a7b444c002987348d921fcb0" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string27 = "537fee794fe5532349360a40d90c0e0e37f9532b0101dbb17174e27cc4aa0d51" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string28 = "568a162e78cabe48a7f30df47b2435b211549e9a7bc7a06f0802b6fc07b7cc94" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string29 = "59156b50c20d44f8757a3a53ebaf4f515b8eb86802ee51085ace7b1f714406ce" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string30 = "5943462569081cec86ed241964fbccf91b4be608c2d647470b19afe31549adc5" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string31 = "5ba1b5f60649f253556fa044849ea7af38cef5337c5061f06004687e0862d6c3" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string32 = "5db320e5c5cbbc14478fc1d7c7ae33cfff92877fc585f83a3d7a981a00e9b4f4" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string33 = "5db3498c96a63ebbf02ce68726110bdc2111cdd4d8bbd3e75d37e8055e8cb3e7" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string34 = "6ef7a5a0d7eb7976141aa9d61242969b0dee3e8a7dddb6259c1bd539b68dcad8" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string35 = "73c49b77b6b2e4032eacfc94d5e5e2bd185fc8ce7eba23ed4ca6921ceb631614" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string36 = "7454351714f775b8391bc42fb94e929c87850debadc69d48a40ac7d9584e1211" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string37 = "7ce28732993dacc199e5f96517aa1d16305c86c623a0e17f9923838e3fa06133" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string38 = "7da1b05ebb0a51e4160ea04db4f70b6e710c14546d5a13169942e4d686bdc477" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string39 = "85a88db7ae01c7735386630ef780fbabdf465b9b9fb1e30e5ea698b114a33540" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string40 = "868d0fe76c71f94336e0444d1b4ce6d7bdd2d0c71dcc2befa9ba1a1d3bb6d28f" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string41 = "93a9468ea39b4bb15148e4845593d36f0137c5a23de9045dc5596a302f873e16" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string42 = "94e25cf9677638da8ddfd84a2c15783e894de90331ed06e9786b1a46df1915fb" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string43 = "975b49f84c3e34d26052f938c50aa5856cccbbdf32e9e4698cebba577ed10c8c" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string44 = "9a33a8d19676646badef58d0a2db13dd763288a2a0fb8452ae2a9f826b27a234" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string45 = "9f9141f57f4d135a00557547091b73f9b13b0af2346082a243e65af90cb9be7e" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string46 = "a583acecdb43cd9b4806eddcf0582ec0cfd9281a2ff821b3d35c4d2dd6103eeb" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string47 = "a71a8916d6a82bcd0d80cc8150699754abdd4c165773438b9ed39515372a4ec8" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string48 = "ab36a5c1f20df8fb1b59154aa6aa83bba2d29a6925fb9ec134457e7d1c95bb7a" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string49 = "b2956027022f69baa93e6c55c69df6ace602d6ad61cb4ddfdaedd4c9be46d7b6" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string50 = "b2b19b7cfc5f45ffcd83e6a099c40ba085cb86c4ab0ac4d0d4ad6aa8e0f40c4c" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string51 = "b4ac2390829f0e3a76c51692d27759ca7b83b4459c4707e86d59c72dbbbe36d3" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string52 = "b62764ff67244482f88ef117bf69d4ee51dc1691f6a62f3feab2dff8e94b9cdf" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string53 = "b7291585c934f4554e645642cebf82f663316646ccf4360f356ff535d2d6c969" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string54 = "b809230b5259568f275760187a0eb5c2cd00a6ac859d92e685036c1dfb797f0d" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string55 = "b88e406cbf20a830e357e89a3e3aa4210829777d43a5fb11d46e38a4220f4d9a" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string56 = "ba7aa4e5aba5fa90f17a2aca9cee62a2b01bb1fc91f6433643e48cdfa4b1c03d" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string57 = "c1c9047d94569bf28c91247cfa84cb49c5d49e37eaae46804663a6d1f45b615d" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string58 = "c3444ec251cca27dd59adbfbc995f095550b7e7e25623f46799e03584845b3b9" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string59 = "c7ef467eeb99aa4aae717d0e258019ab5b7e176da4906a135d86e78faa9251cc" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string60 = /CarSeat\:\sA\sjunior\sSeatbelt\\n/ nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string61 = "cd2e2beff40caf56b5102947d81e825f44b8df24d84f5dc49b1c850f4dca40a9" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string62 = "cdc1690245f3c8749c1ee9744540aa4df2b784f69cb425a967249c057b9799e8" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string63 = "ce75ede7827b5a067bb11a5153e3046286251acaf1e92fd3edf4a46e506b5968" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string64 = "df68fb1553a6d135354adb6d2cc68ea5b0b63569e8d2c6bf5659869cf94ae4cc" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string65 = "e2bff960e45f419ca14338dcdefdcfe25378bc5efa56adfb762ebca92847d86f" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string66 = "e49c11f8f47b6fe4c3810ad8b5a241638983d7e60d240f70859fd4b7a887c4d6" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string67 = "e58c52c3eb69dc4b6cf3a73a42c7a9bc3adc4d0e4728a2a8744715fc730f8b9d" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string68 = "ebef8a0206bb0550926511265edc977c0a75de6dd8a03be4e228cf708ac64c24" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string69 = "ec6e3c3f97578eeeb27f891b19c4504e038e0488293eb1f3c50d3bdc2f30b017" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string70 = "f4c91aebc3bbf867adc0ade2b4d82ffd1753a396143ce8e462b6460736efdbfd" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string71 = "f59b24c1d84e1bbb4c0dc2677bb4010b474eb36a62c54ed1fbbf04d05aaf6a22" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string72 = "f8ffdb3b2c1b6172387a0e776a6f400c5117a0e525a3456465e3de4614555c10" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string73 = "faaafe6256f59d72d96a71d7c12dccb964338c7ef8b9dbf359503ccd2ce79e41" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string74 = "fde28cc5a25646c7b2579cd11a6914077500fabb172f8b44fd56bf9cfbad0511" nocase ascii wide
        // Description: Python implementation of GhostPack Seatbelt situational awareness tool
        // Reference: https://github.com/0xthirteen/Carseat
        $string75 = /get_dpapi_masterkeys\(/ nocase ascii wide
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
