rule PEASS_ng
{
    meta:
        description = "Detection patterns for the tool 'PEASS-ng' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PEASS-ng"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string1 = /\swinPEAS\.ps1/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string2 = /\.\/peass\.rb/
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string3 = /\.exe\s\-linpeas\=/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string4 = /\.exe\s\-lolbas/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string5 = /\/download\/linpeas\.sh/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string6 = /\/PEASS\-ng\.git/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string7 = "/PEASS-ng/releases/" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string8 = /\/winPEAS\.exe/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string9 = /\/winPEAS\.ps1/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string10 = /\/winPEASany\.exe/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string11 = /\/winPEASany_ofs\.exe/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string12 = /\/winPEASany_ofs\.exe/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string13 = /\/winPEAS\-Obfuscated\.exe/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string14 = /\/winPEASx64\.exe/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string15 = /\/winPEASx86\.exe/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string16 = /\[winPEAS\.Program\]\:\:Main\(/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string17 = /\\winPEAS\.exe/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string18 = /\\winPEAS\.ps1/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string19 = /\\winPEASany\.exe/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string20 = /\\winPEASany_ofs\.exe/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string21 = /\\winPEASany_ofs\.exe/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string22 = /\\winPEAS\-Obfuscated\.exe/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string23 = /\\winPEASx64\.exe/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string24 = /\\winPEASx86\.exe/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string25 = "008edaedd37b477a5edd2475fc4e8793b03ec4cba503049a0db2114d4eb18050" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string26 = "008edaedd37b477a5edd2475fc4e8793b03ec4cba503049a0db2114d4eb18050" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string27 = "008edaedd37b477a5edd2475fc4e8793b03ec4cba503049a0db2114d4eb18050" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string28 = "00a2407eb70a40f0054d83e92cc9e8e85b010bfcc75ab5bab1ced62f81622d92" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string29 = "00c868aae54b994cb537e54cb490d665a1d408d2634876bf2cedf4900a2d9c5a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string30 = "00c868aae54b994cb537e54cb490d665a1d408d2634876bf2cedf4900a2d9c5a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string31 = "00c868aae54b994cb537e54cb490d665a1d408d2634876bf2cedf4900a2d9c5a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string32 = "00c868aae54b994cb537e54cb490d665a1d408d2634876bf2cedf4900a2d9c5a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string33 = "01ccc2ba607a0aa44e7bd6690dc5d93001ad70b03ad817142f7f9abb4c911abb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string34 = "026389a44b0e1797d97afd0c333f778fe8c066e9edf4c0b847872263a27451f0" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string35 = "0266d99789720ec1a83a397127c478885b3f3ff02026a3fb06d3a10e523a9cc0" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string36 = "02ac483d126c4b08d880cfab52f1904323006b4778f43f536bb83bb38c2a9f2e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string37 = "02f6a2640616568c5b0f581b1902ebb7be15b6368a2c69ab7f3014754d88b51e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string38 = "02f6a2640616568c5b0f581b1902ebb7be15b6368a2c69ab7f3014754d88b51e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string39 = "02f6a2640616568c5b0f581b1902ebb7be15b6368a2c69ab7f3014754d88b51e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string40 = "02f6a2640616568c5b0f581b1902ebb7be15b6368a2c69ab7f3014754d88b51e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string41 = "02f6a2640616568c5b0f581b1902ebb7be15b6368a2c69ab7f3014754d88b51e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string42 = "02f6a2640616568c5b0f581b1902ebb7be15b6368a2c69ab7f3014754d88b51e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string43 = "02f6a2640616568c5b0f581b1902ebb7be15b6368a2c69ab7f3014754d88b51e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string44 = "02f6a2640616568c5b0f581b1902ebb7be15b6368a2c69ab7f3014754d88b51e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string45 = "02f6a2640616568c5b0f581b1902ebb7be15b6368a2c69ab7f3014754d88b51e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string46 = "02f6a2640616568c5b0f581b1902ebb7be15b6368a2c69ab7f3014754d88b51e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string47 = "02f6a2640616568c5b0f581b1902ebb7be15b6368a2c69ab7f3014754d88b51e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string48 = "03b99b08166cc1f4ef733078b9756cd12d39824acd022a2aca1da5f888094538" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string49 = "03e1412cfc9954592a8c8b93d151ce20083d7a1797b3eb8b15e6098179627b73" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string50 = "046f841782518838690b1ad7916ea33c68cd32cfdd9c87aabc7d85425b0f20ed" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string51 = "050d0065e439ca1d3b1ebe97f74cc4842f40a3b3da609ff3fdc52442af4e7b23" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string52 = "050d0065e439ca1d3b1ebe97f74cc4842f40a3b3da609ff3fdc52442af4e7b23" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string53 = "050d0065e439ca1d3b1ebe97f74cc4842f40a3b3da609ff3fdc52442af4e7b23" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string54 = "050d0065e439ca1d3b1ebe97f74cc4842f40a3b3da609ff3fdc52442af4e7b23" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string55 = "050d0065e439ca1d3b1ebe97f74cc4842f40a3b3da609ff3fdc52442af4e7b23" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string56 = "057432add809186a039ba449a5988101aad9f9e55119b90e34b49e9f14835b3a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string57 = "06f14218e0f7b881a61c998824e6709b313b5c8baaa87a8d15986b0c5cf2b7cb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string58 = "0705092d4c2a8e0475d1f686166b9b1ecb999c0133a0eaf8a7b8fd902dc64930" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string59 = "07400fb1198a8326fead8180f927e62e218885a4940b9879082d2adf49064ea5" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string60 = "0999e7ec2eaa95fded99e6b8cb3ffd5ae372a896731cef3eb5bdb0b8977e64f4" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string61 = "09d9169b42e10b354ce44c9bdb8f06c52506f14f39f6378e52b3c2eac1d27866" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string62 = "0a2dbf9faa4445dfca15c92c6048cfca1e98ad9981f3c8349e7ffa34e62f638d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string63 = "0a33c2da28a068610b62a369635506fbd4a15233867c9c1e3041948006177cb6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string64 = "0ae164e1f157f452b32b06e43b828d792daa447b535b08330f942ade8b87d70b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string65 = "0b3502ac778c671bad537e6433a8f58ec4e1f9a7ab34d37a7bb1bf8c08b2dcf7" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string66 = "0b5f0373ab8388f655fe01309ff6a58e96e969d8a94a06b5a05dce11c998f2f0" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string67 = "0b6a762812a1fbfda681951fbd60bcaa919b99e6e61df84a251f800bb4479a0e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string68 = "0c021fa1272bc222489a6a54e46a10c85d57d758071b310afc66441f72d4a482" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string69 = "0c2c7f0208bac76684a0e8f5960772b22014f417a81caba157b0b512e13404b2" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string70 = "0ca801fdfa8a5040b2e60608fe9ff7fc987ef7d361e389ddcc8d1568b8832230" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string71 = "0d8f5888bc6e02085496b4a070b39169bdea67051b1a9f7af21b29de9615842e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string72 = "0defeb7a564d2f4f237d89ae63065e78af68b0febda5927f25722696593bf42e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string73 = "0f7b6ddc0ef44701c4ab1284610d51d36b4e79d68fb0e184d122533d77cbfb63" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string74 = "10f1654ada84329ad352c7a0879ca49659d8df9a1da87a19ec16d75de2661fab" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string75 = "10f1654ada84329ad352c7a0879ca49659d8df9a1da87a19ec16d75de2661fab" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string76 = "10f1654ada84329ad352c7a0879ca49659d8df9a1da87a19ec16d75de2661fab" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string77 = "10f1654ada84329ad352c7a0879ca49659d8df9a1da87a19ec16d75de2661fab" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string78 = "10f1654ada84329ad352c7a0879ca49659d8df9a1da87a19ec16d75de2661fab" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string79 = "10f1654ada84329ad352c7a0879ca49659d8df9a1da87a19ec16d75de2661fab" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string80 = "10f1654ada84329ad352c7a0879ca49659d8df9a1da87a19ec16d75de2661fab" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string81 = "10f1654ada84329ad352c7a0879ca49659d8df9a1da87a19ec16d75de2661fab" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string82 = "10f1654ada84329ad352c7a0879ca49659d8df9a1da87a19ec16d75de2661fab" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string83 = "1107ec321a60c6b0a500475efd25bf81e12b743c2270cc0482adc7ced6339a57" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string84 = "1107ec321a60c6b0a500475efd25bf81e12b743c2270cc0482adc7ced6339a57" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string85 = "1107ec321a60c6b0a500475efd25bf81e12b743c2270cc0482adc7ced6339a57" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string86 = "1114bbdd9da82e10229805d40ab46ce31fc7a8f57b7ee53d47fa337f5937361a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string87 = "1114bbdd9da82e10229805d40ab46ce31fc7a8f57b7ee53d47fa337f5937361a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string88 = "1114bbdd9da82e10229805d40ab46ce31fc7a8f57b7ee53d47fa337f5937361a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string89 = "1114bbdd9da82e10229805d40ab46ce31fc7a8f57b7ee53d47fa337f5937361a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string90 = "11b29c6bbbcb4bf9dc59b7b308de0da0f13e5f6116a3f10dffe76f4f927ccd8b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string91 = "11cb4947c8f8e84c34512070b1ead707af5e948b82937f32e15df293269e678d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string92 = "12545d5c24427a6dc3e63d63472bb344ad1d67f323756f1430b48ae2acdf322d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string93 = "13827593b510bd2cb72270a7bd4aecfe90043112f1a70b879a36b0eaf1efcfa2" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string94 = "156e71ab72393301c2a27995c869afd9972b5fcf4f3a7e92e8335358f11e0306" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string95 = "1812fedbe3078c546fb0b59bd0d1ef35110969a49515f3c7fd1a519469d01104" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string96 = "18841fe957995a34a5b74eb0a894cad7ee2c10d1c33f1955c1623279e81b9343" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string97 = "18950aed7a4061673d241d5548f425779a3fa89e734a28b2b91fed786894a698" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string98 = "192f251afb217d7b5080564ef78df67235cf0e47bd78a458706a5dd958a9d093" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string99 = "19344cc373b3ed325dd8fcbd5ea333922495486b206c6098c7314f055e194646" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string100 = "1990a0005ec6cd1b0cbfaa53cb51f27622f17e14df230215cb9921e1b2552a47" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string101 = "1a550baec33973542f4a634762c680be12e21c3c91eb62e68558bfb5c96bbf5e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string102 = "1ac39556a986e4338e44ab2e94fcc34fd12cd690feeef22161d255bd1067d7e1" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string103 = "1ada2351bf027363a8dd71c06a73a7450f52f6b85a0bd08e0e51d83b379172d7" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string104 = "1ba53ac62c21cd1f829f4d4cb0ee06906cd3bfd0cf78da267c3b7d9acfb6d27b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string105 = "1c291548b59d3af8b3c225cb7e019b86a3cb706eec437b275528699898bcdb3a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string106 = "1e53b8773c0796d3bed82c67ced0fa96ec2565a697035826a8cec638c6454c7b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string107 = "1f09a88ab2eca35f7e5abd4cc2f11a8f25cd7a060a5c3a943ee88e66fa241dd0" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string108 = "1f350bc4b39f1e89f64366e08af152badfb9756d600b5e611af2433b1e0d3687" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string109 = "1f63e243a7469526eb57f6d08a8d14fbb58290eb999247a005679809fc307edb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string110 = "205acf53b1ebc226645925788768bf52c0701d3227fedc7565cb803862cee602" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string111 = "205acf53b1ebc226645925788768bf52c0701d3227fedc7565cb803862cee602" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string112 = "22048db7a9a636d9bebbce5d6e883f87942a5fe9546341bf66d234b89772df4b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string113 = "233c1188ee1bfe659c4403fda91ac1ce114d9f44f6478cbbe9e8fa22b1e6c600" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string114 = "233d78a0eb44c9b9d7a92ee810f90dec29ab1778536c1b9f5d16c988ac0c70ab" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string115 = "234cfdd1b014e769ee31cda9b6dd0a17c05f028a6e059e5bd4d01175e986dfb0" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string116 = "23779f962171cb3bb425ed7cc6aca741338b9340ede2eb8fa70aad40ddcfca8f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string117 = "2507ccefca7ad5cc4247bae065b0fefb7c3b16cf2d1190535473a05f213d5004" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string118 = "266fa73ded3a2a2dc421e5605dc2fa2bff53d999fe3adebc44ffa989c33061bf" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string119 = "26de444c20c30bd7d731ff5322fca24dc5f442f43daaa5d840edfcc594e17465" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string120 = "272dd72f9bdff7973ed8b642bf8713ece481e208a77fd03b6a24f2b520e1d49e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string121 = "27744baf01464354d336015e1051fdc6706235549f5e62e0230e139eb743b4bb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string122 = "288690fbff02ab86b27552a54a1ded2743a4d819b9d3b2106ee91ee74bcda8fd" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string123 = "288690fbff02ab86b27552a54a1ded2743a4d819b9d3b2106ee91ee74bcda8fd" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string124 = "288690fbff02ab86b27552a54a1ded2743a4d819b9d3b2106ee91ee74bcda8fd" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string125 = "28a29dffc8a5924a97a67798c91db2b75d5b2841ec3c810886fa5554fe2e899d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string126 = "291cf10eee25d10b0ddaddfb68b643dab252c1466fa4e813bb753b19b6604ef1" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string127 = "2b8c3873a05907a9f2d211fdc992666345d060c7376b6e9760fb800a4a54076c" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string128 = "2c96a3a04b62c87a9e5179230186d006f49dca951b230c1db6a543d5ee5ef2b6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string129 = "2cc9517df6d1839ac8bd5077a34ad43f2377e0e4fc9c024f5f9e44b150b94baf" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string130 = "2e179a37f42864951b1151bba266fff17c45e6cacf0fbc8ebf8d8ad9ab45ada9" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string131 = "2ebd756e16d30a5270d5b850eac35b51f1448536adb37e1b415669d51b67c775" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string132 = "2ebd756e16d30a5270d5b850eac35b51f1448536adb37e1b415669d51b67c775" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string133 = "2ec87edb4eba79beefc686363936786094dacb8616bdbcccbec2cefc367f080b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string134 = "2ec87edb4eba79beefc686363936786094dacb8616bdbcccbec2cefc367f080b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string135 = "3188b14bc09838bf33b57704649237b1c1d343189edaf142cfcf9608c4a41e5d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string136 = "31afc2becc2f46a5f993745e453b13146ca804c48eab0c5b41ba859286cad77a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string137 = "329797f116972ec9d9ef719592d687908a2dd4bd5066900bee5452225ca8beb3" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string138 = "337cd6f66f324a1e30d9bae046f10577318da2126f3981dfff99c6def8799bd4" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string139 = "34b4ac22a90064a96fcea9ff8e3f5f3bd089af9672d0e5313d3b1b8f0f0a9125" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string140 = "351268e508cccd1a0bf2c53e605a5db1df85b8c5d4095a4ef0e2d9bb997b39a2" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string141 = "358282c9584c5b32ce5aa55238c71fc7d4cb405e5b7f0ef5e2db4950a4a34b4f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string142 = "363a083ee261a6b87743076d1f38062c4e23d0938817c63dea8716b694c78c7a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string143 = "36a795ba9dfe58c4e8cac8b24ada8cbee9b598dc7af6ee076de0b09750aea29a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string144 = "3727823313bffb3ba255f6bd4be4239a6b6816ead83aa024cec2459e4ef2cbf1" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string145 = "39210402176e6bf813dbff36370978a66505dc7a25008841e5225603ccbcb8e6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string146 = "39210402176e6bf813dbff36370978a66505dc7a25008841e5225603ccbcb8e6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string147 = "39210402176e6bf813dbff36370978a66505dc7a25008841e5225603ccbcb8e6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string148 = "39210402176e6bf813dbff36370978a66505dc7a25008841e5225603ccbcb8e6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string149 = "39210402176e6bf813dbff36370978a66505dc7a25008841e5225603ccbcb8e6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string150 = "39210402176e6bf813dbff36370978a66505dc7a25008841e5225603ccbcb8e6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string151 = "39210402176e6bf813dbff36370978a66505dc7a25008841e5225603ccbcb8e6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string152 = "39210402176e6bf813dbff36370978a66505dc7a25008841e5225603ccbcb8e6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string153 = "39210402176e6bf813dbff36370978a66505dc7a25008841e5225603ccbcb8e6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string154 = "3b02572ebc1fa9eb22898bc2f17f72d50775a18d4c6ff3094ea19e5b5f25c949" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string155 = "3b730f6be970c1671b68792fe163427a15e0fa4426b1d635d9f7e74872f91a7d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string156 = "3cd433ed1ca4566eade23d65399ebc7399e230fcdbde56deb29891e0213aefc1" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string157 = "3ce51c89b8367bae6cae0ff3fa4bbe420df215568e10af5f7b29b3e19048a2e8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string158 = "3e3092fdc0f518823e6cdbff46f7ad327bee6bca9477a826279c7a76bffa7bce" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string159 = "3e55d1d13465cb7e706efa6d4ddf120b35200d694c619889de3d3190236e780a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string160 = "3e667715625410352da4236f16184e38c442b2af48fd6f8899b954578c974c8b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string161 = "3e6ea66956ca27686fdb0b1a7fa1a86ddec39e72aa892958bf9f3b4c5dbce7df" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string162 = "3e95f084c11e971e4b30805e59d4cef87b5698ba21ce72b8a228b4e33c069754" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string163 = "3eca25646f5d9435a6d13eaed2781aaa5efad2a3e512e154892f7a5cde46805f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string164 = "3ef598c9422361f5ce5252d0c4261d88889b51c2c9794ca6a72c6669e77526b1" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string165 = "3f4dc752db705589bdb8e487a55dbdc6891c13c557ec0383701fc5b94d8f8264" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string166 = "3f7216ab8b49c48f550b68c1e5b8d55f10ff60506090ff19e8b6654186b7bf5c" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string167 = "40e7b75207030fb9603977b5b4fb3a8e67f73a243f004cc6eac07114f2ae061a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string168 = "413be3fa27650bb8202b36a93755e57a56faf88d98f38a8c546ac6117c70575e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string169 = "42560ffa5cc3bf26dd9cf38c0bc8e2dbf853646128af8ca713e579023ff42ada" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string170 = "4278e1122672d9c4029ec7c7f3a0e5180d7ad34a24519e80059b8fc9c5ea4df2" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string171 = "438257b96cb3f726b6f796f81c5d72d6c9681f3e617ce272b6250a86496fc9c6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string172 = "438257b96cb3f726b6f796f81c5d72d6c9681f3e617ce272b6250a86496fc9c6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string173 = "438257b96cb3f726b6f796f81c5d72d6c9681f3e617ce272b6250a86496fc9c6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string174 = "438257b96cb3f726b6f796f81c5d72d6c9681f3e617ce272b6250a86496fc9c6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string175 = "438257b96cb3f726b6f796f81c5d72d6c9681f3e617ce272b6250a86496fc9c6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string176 = "438257b96cb3f726b6f796f81c5d72d6c9681f3e617ce272b6250a86496fc9c6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string177 = "438257b96cb3f726b6f796f81c5d72d6c9681f3e617ce272b6250a86496fc9c6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string178 = "438257b96cb3f726b6f796f81c5d72d6c9681f3e617ce272b6250a86496fc9c6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string179 = "438257b96cb3f726b6f796f81c5d72d6c9681f3e617ce272b6250a86496fc9c6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string180 = "43df5040293c26759058a425487affe0f84cdbe1cee85567788f7099782d77df" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string181 = "451d5da48cb04cd5c45c832686019932d528fb51ac0b8ba4ddd4e082291a3bb3" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string182 = "4523836f6c7973deaf94d9b78c9cc30b5b3bbc5859cca5eb88ebfb2f566560d5" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string183 = "453bbd3a1c26955b1ed273f7e206002b49a4a80ba58fbe5ab1b02e4f983c6fba" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string184 = "45793979bc26536a779c1975d9adb745944894941760f1a73f5127e964853c3c" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string185 = "463dd406d25b3d6a4198ff373a8f236333c83f10fe9cff6791f2fbc210a73ad7" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string186 = "46ae3c70f1c7fb28a292eb50e6845b5ebdcdd811b02ec53e8c3007c12d326a8f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string187 = "46e7e0cd3eae7fa11350683e8d75c44e575d590aba9574eba619ccec699b3d30" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string188 = "47c92847c6341aa56ef4979a795844c089a6e87696eeebab2d0411e03b51d79b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string189 = "47d75f99421719d4125b51f91bf7d622133bce0528e5e26051366f6a588d358d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string190 = "47d75f99421719d4125b51f91bf7d622133bce0528e5e26051366f6a588d358d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string191 = "47d75f99421719d4125b51f91bf7d622133bce0528e5e26051366f6a588d358d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string192 = "484703070e9da920db68980b7278e8cbafdfd69e3019772253f70e4d425d0a35" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string193 = "498364537cd2ea03d847b0254255a4e8c2bddc8e27c9dbb901d38dc1f954d99a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string194 = "4ab6038d1b1fa84df1d657c3e46d6d884cd3f646a8a3c35c96ea4885c0b48dbb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string195 = "4ab6038d1b1fa84df1d657c3e46d6d884cd3f646a8a3c35c96ea4885c0b48dbb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string196 = "4ab6038d1b1fa84df1d657c3e46d6d884cd3f646a8a3c35c96ea4885c0b48dbb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string197 = "4ab6038d1b1fa84df1d657c3e46d6d884cd3f646a8a3c35c96ea4885c0b48dbb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string198 = "4ab6038d1b1fa84df1d657c3e46d6d884cd3f646a8a3c35c96ea4885c0b48dbb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string199 = "4ab6038d1b1fa84df1d657c3e46d6d884cd3f646a8a3c35c96ea4885c0b48dbb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string200 = "4ab6038d1b1fa84df1d657c3e46d6d884cd3f646a8a3c35c96ea4885c0b48dbb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string201 = "4ab6038d1b1fa84df1d657c3e46d6d884cd3f646a8a3c35c96ea4885c0b48dbb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string202 = "4ab6038d1b1fa84df1d657c3e46d6d884cd3f646a8a3c35c96ea4885c0b48dbb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string203 = "4ab6038d1b1fa84df1d657c3e46d6d884cd3f646a8a3c35c96ea4885c0b48dbb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string204 = "4ab6038d1b1fa84df1d657c3e46d6d884cd3f646a8a3c35c96ea4885c0b48dbb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string205 = "4ab6038d1b1fa84df1d657c3e46d6d884cd3f646a8a3c35c96ea4885c0b48dbb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string206 = "4ab6038d1b1fa84df1d657c3e46d6d884cd3f646a8a3c35c96ea4885c0b48dbb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string207 = "4ab6038d1b1fa84df1d657c3e46d6d884cd3f646a8a3c35c96ea4885c0b48dbb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string208 = "4ab6038d1b1fa84df1d657c3e46d6d884cd3f646a8a3c35c96ea4885c0b48dbb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string209 = "4b3201cd6976efb471ed4b5f567d9574d0a61871e0aa13cda59b1b8a82852f03" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string210 = "4b611d6813e8cc17dbc5d7ad3359e3f8aa65fee383e6423b846a26dad0f03ad2" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string211 = "4b6c367f1ff92fcd77e8708461c2dbe215a6c44e167089efd8afeee24ecadece" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string212 = "4bb7cf0cb193d6c553a3f11a45b8524a1ba775922e39b92197004f95509728b6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string213 = "4c0321729bb82e936804a1a1f8f76f6ce9906196378d0dd5441e344cda75f129" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string214 = "4c1a18d13cca40ce96d226c7f24c234a236826e4763bf62ba2b18e64b4d608f7" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string215 = "503ed594a822f455532efad9786845a6499fb6de509591bdd37317a469de40c6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string216 = "50a1eed798d16ac30f1bbf50599a29e81de2ac953f45a23174d8b3fb9902d744" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string217 = "50bcc21f5397941a6823e2a5ec6aa8ec5a8f43f7df1513abbaa5b850236ad4db" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string218 = "5117731fa0ee6447f80940c0e41778b000e6ec53673ba2ab9c9eaf5234899592" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string219 = "5248c404dc6560429ff7d6c2fb4cd2dcb379fb9b9c410ddf3f10da2733744cfd" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string220 = "5306a5bf3f43607ea55452f85c45e42aab36652680609b4f53324f8c95121777" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string221 = "5332d9912c90a6b8c7deead3f3b592b5ed63b81e78fef31bfdc04ac3054e879c" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string222 = "5397c248984f9681bec95bd71753e0516bab6e907a0517620a5f7549760e89f0" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string223 = "54b105567f0d98e09c13109f6fc147c79109d413ec542a02a7f20a73a28b1840" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string224 = "54f6d83348b56e49afe082346be15cefa73e4baee6bf3ca909005677117b4262" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string225 = "563b3de7dbb4765e6d4601786536c339df8e29d46a3cd75f19a16c9c8e0b8dd7" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string226 = "569baf3aa71bcad8c0b978885b98edfc91a16dae9d33a03999269b2c43be3224" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string227 = "56c239dd4b23657f74701ab8943f54ed04f251fd4f6c1fa0d532d1c617945dc4" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string228 = "56cf1962ceb2af061aec2e6fd85949b5da5d3ac5da13e9c776f44d15577003e5" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string229 = "56e10f1223e7eedb84c5a96f4374565228382393551941b5e15e13127b9e890f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string230 = "570f6aa0a1c8ad869469cb1dc28b9be6c24fb037f5be2acefbf777dc765eb06b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string231 = "572542904260191ebdf338ac8d2f3dc38057236e8373e35f08f6297850c62f8d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string232 = "58c4d3ad2f3ffb337d715f4233e5e15a97ba83e51be154956e4e173f31aa3de5" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string233 = "59b6bf3d2292e532ee31d4a56b4812671eb90cde840c356ac396df3e2b03fa3a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string234 = "59e73ffcbdfd1f90f12b40c912c742837eb3e6be0333e35586db1d6de7d44d45" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string235 = "5c83e3984dc59f7fee94752fee3f1418b991f6929a21eb534e01c5264b517f41" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string236 = "5c92c2a54210a27db9c368ccdf870dce532bcb272d61bf12d8c5b43da64ee46f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string237 = "5c92c2a54210a27db9c368ccdf870dce532bcb272d61bf12d8c5b43da64ee46f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string238 = "5c92c2a54210a27db9c368ccdf870dce532bcb272d61bf12d8c5b43da64ee46f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string239 = "5c92c2a54210a27db9c368ccdf870dce532bcb272d61bf12d8c5b43da64ee46f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string240 = "5c92c2a54210a27db9c368ccdf870dce532bcb272d61bf12d8c5b43da64ee46f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string241 = "5cac558b724fafdcac0b946daabc39ca78154142a408b62fb59db5655f07e139" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string242 = "5da8e20e1e3a1b63c62d573e8e86316315dffef2b07ca365d0e74552de74b5ed" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string243 = "5ded9901c45d1280311766c52ae096dfefb0204b2ac89f415e310097860e8ec1" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string244 = "5df212be068f9aa481bf48ce088445d2740a15cbdc35e31c3953f5aa27660c92" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string245 = "5eec8d9cc549596b2f6b9bc955202ef6be8e2b74849769904af8aceb477c5044" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string246 = "60f938d08d551800330090458997ee2944fd79478081275bbe609a25a786f67d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string247 = "624f527a957cb2ef90782b1b92d94aa22f1028b731d95536fa318c3c1f211d5e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string248 = "63033e3b8e698bba85b87ca2b199e9c3e7da9d046782343ac0eccab4beef8441" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string249 = "6481fa0be3fd79b6aab74328a3d475b5decec17ff03d0293c2212cbfe53c5dfa" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string250 = "651e8488f87c2dd4524da1169f3abca80e165a6cc22f1355163a0c0e713fb0f6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string251 = "65ddc082f73224383dfe8d9662a428b281c42ea1be7f11f7da241d672dd56a0b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string252 = "65e079dc332288ae073da86cf89666ad53b74e049379625654fe0be59ed9394c" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string253 = "65e079dc332288ae073da86cf89666ad53b74e049379625654fe0be59ed9394c" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string254 = "65e079dc332288ae073da86cf89666ad53b74e049379625654fe0be59ed9394c" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string255 = "65e079dc332288ae073da86cf89666ad53b74e049379625654fe0be59ed9394c" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string256 = "6678fb7c21974e7dbc5948f6c057f0bc4204e7bcd562c5477550f4bb844eba2f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string257 = "66AA4619-4D0F-4226-9D96-298870E9BB50" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string258 = "67ed30524444d6941dc4697249242b34db97c3245bca48fffd1899c027dcb410" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string259 = "694d48564fd66f3c0647a5602f36d2e92cf6ed1291b413232816811e57b37320" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string260 = "69b9d25a8fa177bb4e35424dd0587162177938be90f50a41377f57356fe1a57d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string261 = "6a21863080045ef349eb105aa7e595c2a747b7c42e42756639b4591fea5058d6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string262 = "6a21863080045ef349eb105aa7e595c2a747b7c42e42756639b4591fea5058d6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string263 = "6aa6e18ab15cb987dc3b2e46ed239f7ce5af2df55ace0f7878eddac6f5bee59e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string264 = "6ac4ea67fb65559c2e36fb651cdd4ebcf4817f1e8109db5b0df0a010cb3b95e0" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string265 = "6b6951ec4a702ae5c22c9d7589621cef36e055fda1f5eb5cc9709dfb5d514148" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string266 = "6be513459b23f6fe5bbf0f7654882a2a5a2cb1d19e873e6501fe9768f26c2119" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string267 = "6c0ab655196a8fa5f9829ae8533eed10080676eb37f8603ffe159e82e64836ea" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string268 = "6c0eeb395a6d674e89bc6113467923e8b23a4ed4ade5dd5e5f0c260bd8493efa" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string269 = "6d56de09348b53ca55bedaa5fbef8d37da5c65f1c170d4bae3f63771295bbe5c" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string270 = "6d8bb861a501aecaf9ebf95433d31001fcd529a644be5438c6de49b3afc9d87b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string271 = "6ef8c3bbcd03ba52b59a3f6115c6fba39e9578c0f2c6379f17a6f421f944e1fa" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string272 = "70b62b72b3206c93a43646a86ed17e93151626303dd3408583aceba93fc24c3e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string273 = "70e7482f10e68718812ed28e9511b2e9b005a82ac058153ac761fdfec9a115bf" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string274 = "71d8d1a4ae71b316caf1fae383f7f44aa55d4375c4a0ce08c74ba649251af73a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string275 = "71e371c38e27f1f755a04b2cc3bbe1725c1af2d8d517e96d1702a57e594ba27b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string276 = "7218ab7d2d4dd1e85a6b92afc7cae8e7d3aef7a7add4c5cd8e0ff39ab48b49f8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string277 = "7218ab7d2d4dd1e85a6b92afc7cae8e7d3aef7a7add4c5cd8e0ff39ab48b49f8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string278 = "7218ab7d2d4dd1e85a6b92afc7cae8e7d3aef7a7add4c5cd8e0ff39ab48b49f8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string279 = "7218ab7d2d4dd1e85a6b92afc7cae8e7d3aef7a7add4c5cd8e0ff39ab48b49f8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string280 = "7218ab7d2d4dd1e85a6b92afc7cae8e7d3aef7a7add4c5cd8e0ff39ab48b49f8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string281 = "7218ab7d2d4dd1e85a6b92afc7cae8e7d3aef7a7add4c5cd8e0ff39ab48b49f8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string282 = "7218ab7d2d4dd1e85a6b92afc7cae8e7d3aef7a7add4c5cd8e0ff39ab48b49f8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string283 = "7218ab7d2d4dd1e85a6b92afc7cae8e7d3aef7a7add4c5cd8e0ff39ab48b49f8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string284 = "7218ab7d2d4dd1e85a6b92afc7cae8e7d3aef7a7add4c5cd8e0ff39ab48b49f8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string285 = "7218ab7d2d4dd1e85a6b92afc7cae8e7d3aef7a7add4c5cd8e0ff39ab48b49f8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string286 = "7218ab7d2d4dd1e85a6b92afc7cae8e7d3aef7a7add4c5cd8e0ff39ab48b49f8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string287 = "7218ab7d2d4dd1e85a6b92afc7cae8e7d3aef7a7add4c5cd8e0ff39ab48b49f8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string288 = "7218ab7d2d4dd1e85a6b92afc7cae8e7d3aef7a7add4c5cd8e0ff39ab48b49f8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string289 = "7218ab7d2d4dd1e85a6b92afc7cae8e7d3aef7a7add4c5cd8e0ff39ab48b49f8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string290 = "7218ab7d2d4dd1e85a6b92afc7cae8e7d3aef7a7add4c5cd8e0ff39ab48b49f8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string291 = "740eeb1510b4ed4b7f45792e1fed2296c31f026ccbd07ac4c081ebf019bed957" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string292 = "74320041c8717c6859e9b2c03b5c187b7157bb0c36a0f883192621e3a5f49711" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string293 = "74bc640c2f33875dab29328c3f49dce2658a4b77a38612f11a14c4c100ba8cb6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string294 = "74cab90c0b8c811550b25a010382685337a64086ff2a7b20fd7b5c29c80c8580" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string295 = "754ee0df79ed4346a364bb049f2fd1876287132af5d90a872d2de4dbe53c3c47" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string296 = "7a0bbc4b806f3ea1dd127b03a2ec78d1e6abcb24c1d1aa1dd19eee4d9a3589f1" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string297 = "7a0bbc4b806f3ea1dd127b03a2ec78d1e6abcb24c1d1aa1dd19eee4d9a3589f1" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string298 = "7a0bbc4b806f3ea1dd127b03a2ec78d1e6abcb24c1d1aa1dd19eee4d9a3589f1" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string299 = "7a0bbc4b806f3ea1dd127b03a2ec78d1e6abcb24c1d1aa1dd19eee4d9a3589f1" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string300 = "7a322867ddea562c2a6a1cb9485992f3cec84f2cbf8814261f0cb604bad3958f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string301 = "7a7f5dfc465ba190f6eb0cf36ada4e0dd90d6897c27cf4f6584472a95e828ecb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string302 = "7aac663ac8577e72ee771d1f4aee62c79a8454f3dc6b3838ca567bac23560e2a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string303 = "7b098959bdf3bc80d630a0a5eae9895c54f626a54f43848502ae3849152bd5f2" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string304 = "7b95cdf2630b4e94b8d09bf430308f54487e88928e63bda7a94a75255755809b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string305 = "7b95cdf2630b4e94b8d09bf430308f54487e88928e63bda7a94a75255755809b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string306 = "7b95cdf2630b4e94b8d09bf430308f54487e88928e63bda7a94a75255755809b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string307 = "7be8dfa044e5b3d190e18fba93418c2d30648b35f9aadc3702a11d048b430d71" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string308 = "7be934c8e901153ea188a5003414ea2d18a47f8f404792a27448e383fc1a5e28" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string309 = "7c45771cd7dab73930cec33123a0073e96f50ec035e5b4e3774d3b188441b481" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string310 = "7ce381dbed6df3b62ed0750d769effd075de2fac130236519b76c6c010729747" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string311 = "7da296b4276a84298ef0a70aa516dc49dad526cecf21094d5b2aa42651a25c86" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string312 = "7decdf6084875e659632431939e99c23db088fb991d5102a7646f27f27461ce4" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string313 = "7e2a0b36073628e014853163888d45cd84994109cdc61267706d3c9f63b97ed3" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string314 = "7e51d4af53fe54a5b886d342e26a5b87619c7e1ba29f014012e7e30f157dcd4e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string315 = "7e6e3c02e49c8405a5680d9058fd328683b4f1d10fb9d40d9d16277cc80cacf3" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string316 = "7f461d71b6833275b34bd49c459e07cc6a71aa7263db7fbcaceaf6c154300858" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string317 = "7f94002b26b9570c8cf791cb5adf2b721b678c1b1e07a40ca4aa39c5633b3d15" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string318 = "7fa6c0c97030dea92f7fc81f4fee7bbf42e4fe914832ffb0ce22fe001928ae67" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string319 = "7fcb7a2af36c0dff045a30ff301ff523f8140fd7b35010991fe05e6f16c5a45d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string320 = "8045dd05e50f88b109a05dbd39d98aa7a0ca95d45f62d6aba817a5b257c366f7" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string321 = "8077c66a6fbdc3a6c6a13628b2a5de8a21a366222cd38bed0c9d40901a01c792" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string322 = "80f45afbf7b1c8a0f84fded941cec8979c27d86faea7275c0c70daab760c2908" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string323 = "812c4312270a710b3c4bf47ff75abca809aa51d78f3e8a2e6071bd31dda52c6e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string324 = "81853d4c06bb62f9b8f3032d4ac6aff5839fae7c6ecfdde64a4cd6a538df5daf" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string325 = "8190e7ab106e460cc0e726520b8adf75122e50ce26f0b58db58827c6b6290b97" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string326 = "82ab77802f301f210cd9368128c3ac453fb62f53af88fa912b411dcc3a9f8c0d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string327 = "83eb1e6bfd9d2a628878a82e570af36c4ed59ed06763437a1f957b8cd9799005" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string328 = "84b362a32522fdce071c44b305d146d1e10fbc86641431914c4b4b20d00c8ac0" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string329 = "851b95eb24e83b16404165f2cd2a9937b4b4ec9884bb60c0bce4297c8a67de35" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string330 = "859f9de41d70b9ac3d1fd32c3b8f71c6b73014795e93b7c9b47ecbefc8e089ff" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string331 = "85d455c911c6f67f917c9a9ebb8c42595d5337648d726b9fc0c5b4c94fd628db" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string332 = "87221cdeec621e8f4b489b84dbffb6910c7aaa9e4beba96a8d8419626bf1a3b3" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string333 = "88f176c26ca3b46abea5d783cb01e82eb4c9ce1da3f0184a3994a01e04679934" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string334 = "89789cc0ae92f6b6cc77463942253e26ce68539db7d029c63c46f16f9ee2b489" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string335 = "89bdca2cd5edd0c7e5b3f99ff817f8df7ab449c188dad0f5eae526600df80656" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string336 = "8a2d02874922312a9e7f9bceabd0aca41246bc3bd0a172d149ad357c46d297ac" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string337 = "8adec30a4cdb8fce2a24ab2bfcf1849324fd0639e9ce73f7c250e979ce5df0c4" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string338 = "8adec30a4cdb8fce2a24ab2bfcf1849324fd0639e9ce73f7c250e979ce5df0c4" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string339 = "8af4a9eec787d4d04a62fc1690acb4988bb753e430e38be4754ad24f3af0d084" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string340 = "8b1840ee863f4ae4a930b7306feaac10201344bb6da49401b2673ffc5c9c0f51" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string341 = "8b1840ee863f4ae4a930b7306feaac10201344bb6da49401b2673ffc5c9c0f51" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string342 = "8be40d1c7a362d910cc8c25da987afabb4bb95fd5542c2ab043f2350b7191cab" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string343 = "8c489222246bc16d65bb4b26ad5294a40fc314d9e99bd6feb65d6bc9f0bb7a9c" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string344 = "8ca0c007508cf3a82966fe31b44d3917cb2d22e903bde3738565ffbe88f7fb8d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string345 = "8deed22ba3df2bf2f097be4cc94d9a17651599ccdfead82fccb85fa87c7c69e4" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string346 = "8e22b594e3d101bd26176cf972074d24f850b0f786fdb7254e452183671f03d3" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string347 = "8eac62cb8511aa57cad56fa5b9a7205844ab2b46707e313bf754b520dec23a36" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string348 = "8ff9a955c42b825da52cbc493b836da8604b30abe8ee2fd81f2954066b16ad4f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string349 = "906f3fb4de41cebd2db7a804487066933147df6604e1e9036890dd5b90eb9a9d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string350 = "90f04f9b39cd932003faff204822ac0223a01ae2aa867d6e0992d63a8f40788d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string351 = "913a1f53ad58f76c2ebd3952974eacbb24e01a5b3206a4079b1b111416a70d46" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string352 = "923ccf5c01669104ef312be3e2cf03ebe3df240a45157ad77d23ecbfa6bc0ceb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string353 = "926f9e1e0aacf754734b62556cc9a94961a0f90710b7ebb0b80d71484292d928" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string354 = "928ce67c10ca27f4e598a79b6c4af224a8505e41d9d391f0a0850f715b02b6cb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string355 = "928ce67c10ca27f4e598a79b6c4af224a8505e41d9d391f0a0850f715b02b6cb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string356 = "928ce67c10ca27f4e598a79b6c4af224a8505e41d9d391f0a0850f715b02b6cb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string357 = "942eae7c332725392d235bb8d9e958f77e7d7b0374b2bd4e82d985a33204c176" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string358 = "945dbfc7f7e3ba9e88aa677f30fd6fe9e266e7e88a2e5d4af03ee30b6fb3a5cd" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string359 = "94ca09b07f92e22393a2b6afc541bdd82cb351ab6eba92cc312fde149aac0606" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string360 = "98259461df694aaf1b39e3964495efa332ebcae4e1c5dddcb4169fb0a16fca91" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string361 = "993cae56bdedd0dfb86e91e00180f0162fd0e79c6ee22f15fefdfbf1e10cf5f6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string362 = "99b12a9b146fcbb55353957845dd82e4d809b7626a6438fa46df5c1ba315c45d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string363 = "99db1f18db645ee556d2805cc85df6e31710e7a3a9a3abe4340e9acd61853e1c" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string364 = "9a5eb4fcc3cd9eabc8efc2e39bd091a2b63d7ae056dbcc7a0ee70a505b3f13b3" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string365 = "9a64e10f2857b52c60228b64f832d371781ce6fa6a73a2245400195838d3a81f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string366 = "9a675b01d23c1afa606959ce6c9ef564a32db6672d993fa7ddb0f24dfcba850a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string367 = "9c681c023514a7ef4b402ac5f7225b9daa9244eb45443abfac27bdb684ceeebb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string368 = "9cfdc7b3004cb67d9d6360ff561cd0c3c2c304fdc6ff651aa8ca1d8f0def0c4e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string369 = "9cfdc7b3004cb67d9d6360ff561cd0c3c2c304fdc6ff651aa8ca1d8f0def0c4e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string370 = "9cfdc7b3004cb67d9d6360ff561cd0c3c2c304fdc6ff651aa8ca1d8f0def0c4e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string371 = "9ec78bce4a3ae1586e4bddd8e8becde6f7277b3a63205e3043a175e996c96175" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string372 = "9fa884564bc924f3a31a3f8820a887dd1c26eef4a07511837d9bcf6843c24d69" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string373 = "a00d934514ff5c2821c706fe33d7719980a6c520f152b4b3e6f8ac254e60f059" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string374 = "a0dc0f46eb7ed3f8bd2fa9e1ff1b6e9beb1921bc63e7c72abba2d4a30bec7871" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string375 = "a121163840b57e70165172fe625a054fb1988468fb1a51aed45355463fb3cac4" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string376 = "a1632c4ac9e42fa8bd4f5c393bc40cbc32f9dda8c18bf57e91d575df3c47a7d9" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string377 = "a1670329540c5f64b2f6bd9c192d776256616f94622a002152e4e93515341a75" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string378 = "a243f92822a73f788a7ea29fedbbaf39ce10b70535d21eb8a9ad86a68109ffb8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string379 = "a5d3197567e9952913d0f76422b9a83c9b90f71dabdc8e22eb7dfdcf435ed69a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string380 = "a63286b5edfb067380313b382e077d2a5a671f1fa204f070a9a5513a01857ade" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string381 = "a63286b5edfb067380313b382e077d2a5a671f1fa204f070a9a5513a01857ade" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string382 = "a63286b5edfb067380313b382e077d2a5a671f1fa204f070a9a5513a01857ade" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string383 = "a63286b5edfb067380313b382e077d2a5a671f1fa204f070a9a5513a01857ade" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string384 = "a63286b5edfb067380313b382e077d2a5a671f1fa204f070a9a5513a01857ade" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string385 = "a63286b5edfb067380313b382e077d2a5a671f1fa204f070a9a5513a01857ade" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string386 = "a63286b5edfb067380313b382e077d2a5a671f1fa204f070a9a5513a01857ade" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string387 = "a63286b5edfb067380313b382e077d2a5a671f1fa204f070a9a5513a01857ade" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string388 = "a63286b5edfb067380313b382e077d2a5a671f1fa204f070a9a5513a01857ade" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string389 = "a63286b5edfb067380313b382e077d2a5a671f1fa204f070a9a5513a01857ade" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string390 = "a63286b5edfb067380313b382e077d2a5a671f1fa204f070a9a5513a01857ade" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string391 = "a6465053e2254234650641bb53a2d2f3596439199a8496d724332b7f6d54d5b3" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string392 = "a7f816de8f8e9534649b723d4d61431736966af0d5ccae7ddde2be54755d8ea4" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string393 = "a891ef1cf80e8b8130414970e811828379518218c14abb4c843f4a4671cd3502" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string394 = "a8f1156a26f47cfc7c32d3c403f8d238011e80aa0b066cc2132a1b78e69d7eb5" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string395 = "a96b2bd4b84710a57b236090973820df7aea444d13a671ab573dd422c898dbe4" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string396 = "a9c25f6e6b4a7279424aba73343f268a385a18ca2c735b6e9869dbbaada3aecb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string397 = "a9d77bda6fcac6672b88c4252fce92bc9eb6a00186ace0173f02b72f336d3fec" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string398 = "a9e7d95771dd6c81e46c6c94aefd56695e8f824002532d7a53501fbe645d8ebf" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string399 = "aa980ebc0a241b454e61cba4c13767a8d203993dfd5d42db36a2958f9e6b3621" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string400 = "aab2975ed85ae44e318e705da1bd5d80ebd150affe9d11144473452cf919e928" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string401 = "ab2b75389dc3ffb194e335af335d6ba22abbc0e56815eb4f5fd7afa9ed9e72ac" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string402 = "ab64b46723ed98b58c91128f0e7fd806ed1a2fd47e1960ff12c68083893d86be" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string403 = "abfd58bdd84c727b71ed7091ae3865a774c9d838b3eaf1a6b249119234d83a71" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string404 = "abfd58bdd84c727b71ed7091ae3865a774c9d838b3eaf1a6b249119234d83a71" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string405 = "abfd58bdd84c727b71ed7091ae3865a774c9d838b3eaf1a6b249119234d83a71" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string406 = "abfd58bdd84c727b71ed7091ae3865a774c9d838b3eaf1a6b249119234d83a71" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string407 = "ac2d0b0b024bc8584bcaf30d16b3ccc876fe0fca14e2907e56b928514c8d61c6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string408 = "ad94977a2d07c55c4b2106b47bd640ebc9ed21c8883a69a998604a4b4109288b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string409 = "AD9F3A60-C492-4823-8F24-6F4854E7CBF5" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string410 = "ae85963af2849bb420e8b9d1e0d7f2194bf07d9b0d4a85fce7e5c40651626adc" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string411 = /aes_enc_peass\(peass_script\)/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string412 = "af2f2426e9f2614350859b5bc05cf72138e5a5fbc8dc06f22c12b929deaf340a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string413 = "afca48a465dd8ee9d44677c4ebb9d71fc66adae3686dbff6b3eb139ef2306f7a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string414 = "b05d1b0ab92d9c5cfb3f0db593cc55ba5a4c22dea4cdf731ca8b934a45163ab8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string415 = "b2992ba236d1f4cffb77149e3c67a19d59f8131249e3ffc16b791ec2522b9629" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string416 = "b416c391df9c944901ea74a04d71853eeabb63f41319efedca9506f6bc8f23e3" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string417 = "b5b45d5d5dce3e17d8fe1f7a8e14f0746ae1277023967dca344c61f34e4b442e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string418 = "b5fb07cbf59469e3e6716bde4e85056b27a27d99e3ada1d8b75bbbcfd4c1198e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string419 = "b777f5e0912b17dc92eb667dc845f2af041a98d6ff189c00e806f6acff5fa231" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string420 = "b8e498773afbb4d216be790053b45824bb4c884cb96fbe486209418251d9f737" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string421 = "b936913f0aef2efd1184619af801739258328dd3118d8693dd02811aa6ac16cb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string422 = "ba5925e3a8778e1bf0a38085336d8cff3bfe162fe425bc5a93fcb8ae5bb7ebfd" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string423 = "ba912bf7875b66acdc47babd2884d56d240eb07eda2a9384ab0dd79f2e29f252" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string424 = "badc29afa637d3950c1fd837122c4f5d21c2eb431f3e44fec420a9281e3fbbe1" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string425 = "bb949fe0fcc794116d8972a418314c97d0e39c536a56d1858866ff8eb6a46f02" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string426 = "bbf29036cd4d73fa71e311d60c436a4c03b72d2ea9b9c450ca9a88bb6ce98a03" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string427 = "bc6e01140eef4c7579635f731aea2b4658c733f25dae67a3f56fee8316151a27" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string428 = "bd08e85390117b2c3fecc447cd3009e3fff3d402e6853f5d06bf710b5cab1bca" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string429 = "be1329d07bf1b6f6558c7f95103c773d70eb68d652c4da6143f581332141a954" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string430 = "be46cdf9a5079ad20e237f131383bae6873297c3cff36ccdde274c1b78935810" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string431 = "be46cdf9a5079ad20e237f131383bae6873297c3cff36ccdde274c1b78935810" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string432 = "bed163d2dafa8fc4074ece57cdb10edaf275ddf5599375b9d58e025bd0cf42ef" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string433 = "bf52295b55072f08f18712abd36ed4c4c276c7affedb57e6e54d7fd2bc7e0b9c" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string434 = "c28b90220de9396746da9507ee9e7dce146c67781cd3a176c6394b52655d60d9" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string435 = "c34383371ae8b87dfd95ae52734239fa51b164c15eaabc18c40ba950b75e8e9e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string436 = "c35130a44f7eb55c4a2a28f50d93e98ed60b383b5697ec09a7fe26fb52505a88" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string437 = "c36ad4e21ecf39ba3c2c9c201c16dc4a54b46831d893f31865b95879d6487c7b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string438 = "c4645180927fea47c25236d1ef856476f818b04d048042577cc4793f4d1dc040" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string439 = "c4677593f3d871965055ff5c05412b2a6a0f70bd8d7bdc33c409bdc5669b925c" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string440 = "c53a7f81553bb2d0b575c48c194a100c9d10dd08f6c7538c92a9db2080b47792" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string441 = "c583cc6e021fb8b1d77bf028ea18748302ea8d7a142f875d87414358c7a94f30" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string442 = "c583cc6e021fb8b1d77bf028ea18748302ea8d7a142f875d87414358c7a94f30" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string443 = "c583cc6e021fb8b1d77bf028ea18748302ea8d7a142f875d87414358c7a94f30" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string444 = "c583cc6e021fb8b1d77bf028ea18748302ea8d7a142f875d87414358c7a94f30" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string445 = "c583cc6e021fb8b1d77bf028ea18748302ea8d7a142f875d87414358c7a94f30" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string446 = "c655df1762fa005766377fa896d4cd5537cfb055231e56f117479cebba1d5249" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string447 = "c74ba7419eb8528b153e3cb208fd06d0012884b1528fa4152aa7ee034d956a63" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string448 = "c87b427a81ef1bd26dae10308f7e4b81e1c27a535aa17da16270c458efe51d77" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string449 = "c887fef4396ca2a13d0696810b2ddceb2e825ac75e9a4ec0bbb9dcbd3f7d8f5c" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string450 = "ca2133708cc46f76d99471f39e68047c931a2f7b9927d89f010c042ac97bab80" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string451 = "ca3dcfb3f0b373014cc646ecc851c83f5f44ee341073b51b536b2ee0caa84bbb" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string452 = "ca7851a4dd97eeea65e46725df9dcd9de9c1aaaec270830a131fd821b23809ff" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string453 = "cae4832509fdd3effd709ed3b7549d2472d9c11ad06121b295d03c6a4699b85c" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string454 = "cafb5561a99ca3e74b06e53a71967c69d7037985652179031acd7ecc89704200" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string455 = "carlospolop/PEASS-ng" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string456 = "cc81556dec6e809ac1b518fc24e1b035e1b82dd57aa7f78606332e1d40a2add6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string457 = "cd590c74718bd7644e143882c28506b16b13647e4bd0eda856e179cb3de1ee59" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string458 = "cd590c74718bd7644e143882c28506b16b13647e4bd0eda856e179cb3de1ee59" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string459 = "cd590c74718bd7644e143882c28506b16b13647e4bd0eda856e179cb3de1ee59" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string460 = "cdc7e13638e63b48b6489c35824ee07af51fbc5b0231e220c993f95d4554b673" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string461 = "ce26833cea9cc46a3fc2b6418de85ce94dd4d190cca15757ba40fec475487e73" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string462 = "cee0283b58fa5fb0742f230a70f8a69cb283914e886d7a332b22eaf25b48f4ce" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string463 = "d01792b1ae73080ae4983d7d1016fd6927718b5c9543810b5daa9f2b75520928" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string464 = "d01792b1ae73080ae4983d7d1016fd6927718b5c9543810b5daa9f2b75520928" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string465 = "d01792b1ae73080ae4983d7d1016fd6927718b5c9543810b5daa9f2b75520928" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string466 = "d0679dcc64ecf46c8ac74974a340e254ecd4a9fc4db26ccf43b94e2f71ff6eef" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string467 = "d1c7ff29ca273c6d90c5607f57a7788c3f5e569bc2c2863edcde5f2653bbde81" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string468 = "d2910692ffb6571d6017e93018699ef5b29d8aa30b0020729569bb5855460c72" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string469 = "d2f2208befd430af548bf911e596fb11381d60179caf6a8b80d1ded689787e16" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string470 = "d345588bd7855b93993aa01e5c36cd6f9c1690277704d24a6121fe8d05f93d10" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string471 = "d37d33ecf520439042e8ed6d68c35599b6a665564ff1c6fc863ffa0156d0e0dd" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string472 = "d3876cdd08d5cc314448e50b35e6dd7779925bfeb93f6309b12e1e234f832dde" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string473 = "d44bdc842118dc9ca7fb8d4d8c5a9e4bfb50f1e28daacdec3e4e6840dade446f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string474 = "d44f92ca48ad740a9ec34a5022ad904fbba74eba78b9b8a2a353c0ef4587e682" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string475 = "d8582bc308f3f5364747243e689c59401ba0d5a61696bdbbe04b699eb837724f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string476 = "d8582bc308f3f5364747243e689c59401ba0d5a61696bdbbe04b699eb837724f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string477 = "d8582bc308f3f5364747243e689c59401ba0d5a61696bdbbe04b699eb837724f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string478 = "d8582bc308f3f5364747243e689c59401ba0d5a61696bdbbe04b699eb837724f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string479 = "D934058E-A7DB-493F-A741-AE8E3DF867F4" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string480 = "d9a081fa68e6e0450c6f04497d7926f1e8a2fbcc2893ffeffe6aec1ee1ab283f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string481 = "dc229f8b0113731ba7d73a24c9951a9511067c151fdff7f4bb3b3ec8a55fb287" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string482 = "dc23ff9df3352509e1d8c461f0ac98fe52c1d5ab5c264c047da4afc2cd6df87c" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string483 = "dcef9a8f6aefcf3bbd1facfea19407604e12bec996f162e7bb2d7e0ae0d6e5db" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string484 = "dd3dc6677db3402e952a4e127c19ed19a0a95772e2353734af4a94f61a27f580" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string485 = "dd6a39d94965fa111cdf668b932ada92a4da94aaf90a4d3d2bd13f6232372b77" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string486 = /dir\s\/b\/a\s\%appdata\%\\Microsoft\\Credentials\\\s2\>nul/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string487 = /dir\s\/b\/a\s\%localappdata\%\\Microsoft\\Credentials\\\s2\>nul/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string488 = "e13e6e6152026be625cf8af27fa44e767f83afd8aa0d0db0f7041075a8b647e7" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string489 = "e1bab498bacf77137139b848d080c2e4cb7d7e6b34573ec309ab3268de4ba089" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string490 = "e213ddff412e4aaa9a0cd6460b14cc246a5b33e60f76440482e0142b8a239ff9" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string491 = "e21f6e3c1907732a3654077febd8b675cab97d2ef3529e8dcfa6ce16ffd80967" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string492 = "e21f6e3c1907732a3654077febd8b675cab97d2ef3529e8dcfa6ce16ffd80967" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string493 = "e43124c3412c5ced1b7c4ba34ecb012904d8b967be3a3ea0f5da507518c1f6a8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string494 = "e48d5d119ea5afc1586810a87475e8e16e0c7bf21af747ec77396f27ff5ad21a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string495 = "e4c23b8fe00672ae95277e683f870456debe246e506a7ff47c92c1881c5c7622" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string496 = "e55bdac582b5e2b4a3fe52e6c070f2c313d3466ed7ee58266cba3a74c1542f91" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string497 = "e7bd6debd460c7b76bf0f743473f741b095d9410f063063b39537f2d01928e2f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string498 = "e83713071664d8b6feeb9c942f05dca3ba4951ac55743dbaeb79933f4728967d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string499 = "e8a6280ea27ebc3633c9976efa12a8b00b995e6234d03bbfd802fe118c713d1a" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string500 = "e8c954604c706d3a252049c1e639abf09fb55b90f97b1957895063b6fb8309d3" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string501 = "e99068fa60039d7b7ad0969f858f228134218014143002abf149f220388b19ec" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string502 = "e99068fa60039d7b7ad0969f858f228134218014143002abf149f220388b19ec" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string503 = "e99068fa60039d7b7ad0969f858f228134218014143002abf149f220388b19ec" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string504 = "e99068fa60039d7b7ad0969f858f228134218014143002abf149f220388b19ec" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string505 = "e9d6c9f3eeca8db9514443c50651c78b29d68756495d8d973c8d5c00123750e8" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string506 = "e9f65ac196e97ded72d97f6aa514c544c0d660983223a2cbefb6ba45a21973fe" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string507 = "ea757b0016ff6287429d657cc4197ad6cc0f2655ed21a3a9a86952a085d65be5" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string508 = "ec1e39774b339fa1939d8b970961041349ecf364ca612d376a42744db8132223" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string509 = "ec5eb13c414c6ab275ccf7b1b142bee66a5002846c6eea22e2c722705cd7cfb4" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string510 = "ec64054f2ecdaea42d302fe63e1cbb9835998e492ac017d0ea7f2c24bc4c11c2" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string511 = "eccde00640f1c9f27b63f1a778eee3c50f401f62fbc0e8725a769b8bfe869e70" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string512 = "ecee4a34d7e86b3445b1ccadefe2e5587808cbd1a1f1408fe63ac3c2aad84d2f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string513 = "edf9405f4286e33ff63ec5b16f35981f52ecc1404227b043e8022cadbc01b925" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string514 = "ee8088715ef996a3be6d9b935086527556473825d7908573853c1ccd8aa8b26d" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string515 = "ee85ccadc62f1fac243dec2da0ff38e21629cd84d56c500eab76e329cd48be61" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string516 = "eed0e9350a87338b0cb8e78ea1bffc7d3c08ae221de88a3c94dc0eac0a456fe5" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string517 = "eedd5f237d110c97db52b4b3970fe3b09453120d2efcc8f6fc0291846c25edec" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string518 = "eff99cabfd57fe3076ee55bc66dd96af5750307b7766234ccb1327b6ccde47ae" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string519 = "eff99cabfd57fe3076ee55bc66dd96af5750307b7766234ccb1327b6ccde47ae" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string520 = "eff99cabfd57fe3076ee55bc66dd96af5750307b7766234ccb1327b6ccde47ae" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string521 = "f06f0e1867889b5f70cbb8e9050d25b8801c15b93fe4b6a4d00841c6666ab0a6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string522 = "f0f81571b19a8af0b074b80fc965fef5c2afa705143cade50786d944c24a0494" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string523 = "f12a335a790c4d47c3eb5182ec43afd523dc6ab354645f0167fe7206073b61e5" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string524 = "f17e974041fcd977a7aa0171c31af287be975d6095d91ed5c5773446d7379bbc" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string525 = "f41834034f704e3f0a17ed534124e31052ffd449de3be29d287faf4933ce7c1b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string526 = "f5776b57d23638d930bcadcfe6b2b2bbaad668472a74843a52d0a512093a05ed" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string527 = "f5a0c01add702bb0f03e9e22d30242012cae3e5132a5de9d4888ecf987f3598f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string528 = "f5b818bbd0a230ab8f0e533b563f678ec774216f4d06e4cc90d0e2e61167eb57" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string529 = "f5e88366bd0d54ec11ea8332379c570a7d796b1f1bcc3db74d016da1367725ef" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string530 = "f66678009d2d605438bb2b8308cbce9b05aeb25a63785c228e30b52c8e43af75" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string531 = "f6b986ccaaf37e82ac9dbea5107d35af95b18aff0f33450c9876b051e2e6ba9c" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string532 = "f70320403ba17e7643e7bd26f62bf42b6c01e184d40a2af0f5b46608d31f79e6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string533 = "f791fdf3865ad607dcc1f0d7f1cd52ff8eb6f976a9b6f3f48fe1b0c3d73e3fdc" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string534 = "f84e42c96d58d814d41f2301f242cb7ad50f0992509fd73562a60afb5449c87f" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string535 = "f85309eaf180124b677cd1fc086b3357b607b33482a8e562cfec767e4572bf01" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string536 = "f868f99f4d8dd6cc691fccb21ceb5cfdf84406bc7718662f62cc191c33a13538" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string537 = "f9d5a4845037c07016edfcd1510066195d7c86dea9db7cbf93b0f7f6c2ba0e3b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string538 = "f9ee736ac087001620103f7f42f06cbfc4aa7e37d7f2e1f9b0f10abd6c4349b1" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string539 = "fc86f22cd93a4256749cc54df8e9d35efc8d6cd43e4bcc90c6ab212761975bb6" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string540 = "fcf4797042105ca349abdecb9d724dfcbb92300ff3d0881d90c311cb35fd5338" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string541 = "feb92ee6c4408e3e4b59d0b51220cfcc2b4713cf53a15da2fe4d27e7c5f74c0b" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string542 = "fed5d8a2d027d38ad43fdfc4cfc9d8a7c6aa93384f8da45955042fb83c8ff52e" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string543 = /https\:\/\/book\.hacktricks\.xyz\/windows\-hardening\/windows\-local\-privilege\-escalation/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string544 = /https\:\/\/t\.me\/peass/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string545 = /https\:\/\/www\.youtube\.com\/watch\?v\=9_fJv_weLU0/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string546 = /icacls\s\\"\%appdata\%\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\"\s2\>nul/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string547 = /icacls\s\\"\%programdata\%\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\"\s2\>nul/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string548 = /icacls\s\\"\%programdata\%\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\.{0,100}\\"\s2\>nul/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string549 = /icacls\s\\"C\:\\Documents\sand\sSettings\\\%username\%\\Start\sMenu\\Programs\\Startup\\"\s2\>nul/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string550 = /icacls\s\\"C\:\\Documents\sand\sSettings\\\%username\%\\Start\sMenu\\Programs\\Startup\\.{0,100}\\"\s2\>nul/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string551 = /icacls\s\\"C\:\\Documents\sand\sSettings\\All\sUsers\\Start\sMenu\\Programs\\Startup\\"\s2\>nul/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string552 = /icacls\s\\"C\:\\Documents\sand\sSettings\\All\sUsers\\Start\sMenu\\Programs\\Startup\\.{0,100}\\"\s2\>nul/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string553 = /PEASS\-ng\-master\.zip/ nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string554 = "reg query HKCU /f passw /t REG_SZ /s" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string555 = "reg query HKCU /f pwd /t REG_SZ /s" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string556 = "reg query HKLM /f passw /t REG_SZ /s" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string557 = "reg query HKLM /f pwd /t REG_SZ /s" nocase ascii wide
        // Description: PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string558 = /winPEAS\.bat/ nocase ascii wide
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
