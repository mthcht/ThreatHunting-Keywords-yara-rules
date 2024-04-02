rule gosecretsdump
{
    meta:
        description = "Detection patterns for the tool 'gosecretsdump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gosecretsdump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string1 = /\sgosecretsdump_linux/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string2 = /\sgosecretsdump_mac/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string3 = /\sgosecretsdump_win/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string4 = /\s\-system\s.{0,1000}\s\-ntds\s.{0,1000}ntds\.dit/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string5 = /\/dumpSecrets\.go/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string6 = /\/dumpsecrets_test\.go/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string7 = /\/gosecretsdump\./ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string8 = /\/gosecretsdump\// nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string9 = /\/gosecretsdump_linux/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string10 = /\/gosecretsdump_mac/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string11 = /\/gosecretsdump_win/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string12 = /\\dumpSecrets\.go/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string13 = /\\dumpsecrets_test\.go/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string14 = /\\gosecretsdump\./ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string15 = /\\gosecretsdump\\/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string16 = /\\gosecretsdump_linux/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string17 = /\\gosecretsdump_mac/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string18 = /\\gosecretsdump_win/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string19 = /\\impacket\-out\\/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string20 = /017c2b90e43274da40ed0346587b5a2d02af576b305b882eb31806eb7509655c/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string21 = /0b6c277ada6299603f6af3a2ec7bf7134df0c71d8f45438eeb65a2455d351e27/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string22 = /0c28929dbbc6cfe733ed93670025f18f03642a4b323d7fd123ae63c9366afc31/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string23 = /189f1c8815a6add9af140e74c2a8ed875e1d2187c42de7180aa99030d2002482/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string24 = /198dc4828f294ed26c63eaf2c0d38e2d7a21db41fe31ce988d9139ea2245f0ea/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string25 = /39f0a8aa528f48997f9d2b81845eb9f7fbdf6151f34f883ee30da4649cc151ae/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string26 = /3ac89800bd6dc53207c19d3d35161342cc19bc09a212710393ec9ab79fb55ba1/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string27 = /3f511ce7fdc81166c2e8811560fb1a2b30b5568ccd184d915f23fd5494cd969e/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string28 = /42528d08f25fcba2cb6088f4a1d810a1c1783ee3af573204094f81c2a4c0765c/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string29 = /6905595a21a2a1d669fb80a6fd3f97db4692d98ad9e33eae64466c7cfbaabb8b/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string30 = /9ff84ad7a284229d49078e3bda95630c060e7845e94169065b47e285795747ad/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string31 = /a315f75d50a2c54a6d1bb84cca077e6894870d8a1e60010ffd1307a295c8b9f7/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string32 = /b2929f86fa6ae92dbbe1efe6e8523ed214beea67b52e6384ee22116689c0098e/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string33 = /bd7552c78fd3f852e39b140051c4a1aa5a30a14e23eee49cfb570e19b4dbb0fa/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string34 = /C\-Sto\/gosecretsdump/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string35 = /d650f132e50bca7c7a06965617a46e32e68f1066cf15cf04c2759bbcb81fbf68/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string36 = /d780134609e2b5c9ec6b75e35c5f6eefcb1527105a584c6fbcff5dee33cebd37/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string37 = /dece45d516d8421e39684618e0b571f94d31dfaf0d0d20d6f4593f4ab67edb0b/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string38 = /ebb285411e3ba9431b7c211c1e8ba97753699805f03663cbc367798b4db2c1fc/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string39 = /f4f736012e96fda525525508fdfb99ddd93d1e114b1a3b616234f6c47ffb84c9/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string40 = /f6efa1ba7a66dddb2a14a652d4f96f365c73e3b15f5f40822eefbff9fc46a57c/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string41 = /gosecretsdump\sv.{0,1000}\s\(\@C__Sto/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string42 = /gosecretsdump\/cmd/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string43 = /gosecretsdump_win.{0,1000}\.exe/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string44 = /hashedBootKey\sCheckSum\sfailed\,\sSyskey\sstartup\spassword\sprobably\sin\suse\!\s\:\(/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string45 = /pentest\\\\sam\.hive/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string46 = /pentest\\\\system\.hive/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string47 = /Println\(\"DO\sWESTERN\!\!\"/ nocase ascii wide
        // Description: Dump ntds.dit really fast
        // Reference: https://github.com/C-Sto/gosecretsdump
        $string48 = /secretsdump\.py/ nocase ascii wide

    condition:
        any of them
}
