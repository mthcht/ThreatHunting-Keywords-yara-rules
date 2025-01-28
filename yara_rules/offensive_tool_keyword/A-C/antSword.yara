rule antSword
{
    meta:
        description = "Detection patterns for the tool 'antSword' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "antSword"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string1 = /\/\.antproxy\.php/ nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string2 = /\/antSword\.git/ nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string3 = /\/antsword\.tar/ nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string4 = /\/antsword\.tar\.gz/ nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string5 = /\/AntSword\/archive\/master\.tar/ nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string6 = "/antSword/releases/tag/2" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string7 = /\/antSword\-master\.zip/ nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string8 = "00758b7af992689b4d0b128b19582828b871c4332bfe1d9732d39118099b398b" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string9 = "00fb3eb58122daa2d401298b41db03757020c44cd4a41b664be65bec45008f63" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string10 = "04b631a3a34dae8fc3ead9204c21c2267aa91d516327453b588708c8c819c891" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string11 = "063e8e1b8a6994c10bab6ccc8472674dac510c2417864904970a5d9e5626b030" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string12 = /104\.131\.124\.203/ nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string13 = "12478b22d1d04c87d681a635c8e31745119c25d50bf344f6ed9d8a4cb65e96c5" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string14 = "18425e36ae11253b1bfe0a4cd5a291f33709e3199d7598a39fa91efa4b8d70b8" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string15 = "19c66cdf6c01ddd42f8cfef1e843ee5f8d929b05135190e9ce0c988180e7439a" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string16 = "1ba866ccd7462b3d78f20e76558f9b7ab94a3f565ed6261c60078de511dfc461" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string17 = "1e522857a95073072b70cbec8abcf0c0a3b4603390355fc077fac998273e017e" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string18 = "24e3451e7466a3c1bb84250a85fdd4b004856c8087458119ccfe1631877f5e3b" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string19 = "2d5d11ca0c75a828e3345af626a7b45bde92e1425f5d4fb1c178b7751c5c38c4" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string20 = "2dbdee080a73de51397300d3d17317f6a20e81e57322ff8ede6979ce81349405" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string21 = "2eca40d1fd4b3aa09ddc3985141276cfc74b1f885cd3e65dbb7bfde0ef22c033" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string22 = "370d1dcdba848da3c77a39eef3ce5627005f8d762df8e26f8ae6b0bdd16b2323" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string23 = "3890a3df1d59c7b9accc11721287353ba992630fccf9ffc9361cb7184af8fbda" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string24 = "3900ecdf76a186de3454e3f2dd45b338cc46cd855e2a027160f3cf6a25385482" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string25 = "3d505640278c986f4d6f644c64b28b338063003e54baa3826907c1c235a57c44" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string26 = "4549092826ddbd01de6a9d05e0146ca12544e98ed832cb9308dc8d11c4a987d8" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string27 = "481dd18cb726fa8637461072ba5149f553ba72ff68bc0b28d98bc3bee0c5488d" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string28 = "4aaaf489536ec7521629fda215dc34a1f69836a77d29d44d2dbdd6da4bc2c250" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string29 = "4f147344cc3252a3d59329031202725bc65f0ef58d41cca6fa24d5fe462fc84d" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string30 = "5073563a45bb315d8f02df7058cb92b2b285160c90a159fc2e68e1a17d807bba" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string31 = "50cce787f7b403a73b352913648361af2949a21bb85b081acccdecc1ec4c63f4" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string32 = "54bf6a4dd21e76db385e1a4dd952e74d28711a8fefdf802c4da52e4740a93116" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string33 = "5aa96be2191beac9ae36173638b5d98d6ce133676c42438f2c8d86f22c2b2232" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string34 = "61b990b8dd868920a48c4f599a255173824f5576db1ad712d331dc8f57e5a05a" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string35 = /67\.171\.34\.23/ nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string36 = "709122fccdbf1d9d88fd3d6d52968feb83a696ff4504f1a26ce562707b0cc94a" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string37 = "710db84c96a19c705db2d2111576fd459c7d999080462000cf93d02733e4521a" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string38 = "7442b80cbef6b940d332c3ee1f640c8b7c61fbd833895da3b58c72f5e802765f" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string39 = "78bef84073c09246a6acddeebb63557e60236175afc68408981a517c7e08d326" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string40 = "7b49173186a78fa01b47056b8a3304f8f8b9a8d83bf2a0a342fa2e5597d745fb" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string41 = "7fa350350fc1735a9b6f162923df8d960daffb73d6f5470df3c3317ae237a4e6" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string42 = "825b4d331afd5cd191607e13cf649bceb7aa5eaf90451538a8953b5052ca7502" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string43 = "83af4437fd36d6c244dbf04d1318195103d981ca4d2f2db99e6593ed74c00ec3" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string44 = "83dd381d2122ba8b3552661dae64d149b4bcdcc9f7725b482574fd617db2ddff" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string45 = "84e209caa4eaae874620fbba2fb4a0ab9b859aa1e82eaf7d36791854b3d0e76a" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string46 = "89781c80b442ef36a857bdf403b7ecf12e9876a059ec81ebae250f387afbec63" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string47 = "8a3d9dde4d2e42261f08cd41acec9917920b1b926471825e0c10751c14a53cad" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string48 = "8ec72b1306f2b9c3b620926db69784d38e8169d3eb58d5db2d670d839e622765" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string49 = "932450a89ef9c5b089ddfb917b49e1e8cd3e001133081f0baedffaf0039f004b" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string50 = "97cb8247ff30cc1aa0bfd279da92894f288e4bc985441f10ababfe22caed984e" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string51 = "9c84bbd09726eb178ebe16830e8e126edf4f25db3e22721c64f4e42dd3e70f24" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string52 = "9f9b1672144c23acf6b5d94fbb84756253a0dc4240b19ff4b7c5e73e38c2e6e6" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string53 = "a59fce8872204dfb9885c0b1df12dd0da813aeb281699bf785783265fe27c415" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string54 = "a9ecfb28564d208704c7463424adf0f1b0e10cbb789cfbb7bafc9e1edc8ec4cd" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string55 = "acda112d8e7cf13a8d91628d58d53b7099fc9ae7ecf8e0b6b1c86fe6a8f0ef2d" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string56 = "AntSword JSP" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string57 = /antSword\/v2\.0/ nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string58 = /antSword\/v2\.1/ nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string59 = "AntSwordProject/antSword" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string60 = "b16cdc0e46842b871c8beca3caebb6aa33ce0d8404b787f053dd31511c919fa3" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string61 = "b430b05f0f5557426217c9a5a94f87521264b47398183c8715cd1615a7ed645e" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string62 = "b765a6553f1916e7ccaf5ad4ea8cdb5cbb8539069c98538e4e163dabd6d998f0" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string63 = "b85083493e392d40d01bec390adba7e862fef08f3624839bbd9aa4f1b049fffc" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string64 = "ba873651f323f87c83b99bccdbb136706dd1bcdc5fb29164be0bd8ebff2770ae" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string65 = "bdc2686a36e42dd3811d7c05c38a29d1c8107c6fa8a94b194255857bbb80053f" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string66 = "bf36e85524877406694ccb4591a92b344b4e2778cedeba1dfac0ce1a30a4f80c" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string67 = "c09008db98890127c9d7b2c86260bb670f7768c8310e61fc45707feee6afd25c" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string68 = "c5ca918f2d912ad4e74640d86a6f1da1845eb96f3193b71ad7eb231b0ce1d2a7" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string69 = "c7070018339311195621126010bad10ffa062b36835b834a16a648d5e27aeece" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string70 = "c75531e87d48c7411c2af2775fa62f4e0ef5b71103ef88cbbbbb544ed76279f8" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string71 = "d06ca6d1ef102f243774b1c4da1cabb414b015e7982c8eec3b54dbf728003248" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string72 = "d5dff22f4db5a503538b01476f60d8e0fc9f203259866eeb96b551fb2271cf65" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string73 = "d7add2812de595a486a90bcb598d1ea630254658610f0e19d42af814b8dfa822" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string74 = "d94ce7fd1fd2012d893891f6577ec1f978aea6165d003120f7d057f25e767645" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string75 = "dd820151677383a23da1dbdb9647a05b780146a0894502d6ac3a93c51e885cdb" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string76 = "e0f7ac87107e30818d287964478bfef438a388682656a428099abeda00375f1a" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string77 = "e19603f3ae1a655ed21fdf9544e936b4510704024aeffdb69125d87373509e88" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string78 = "e7b05678d111dcc2cd46fbe74c7febad2d3a51121bbecb11852e69d332489b22" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string79 = "e8dc7a34e869e6e7858a02be0ca8f799a4c5c411e4297c6df0687157bd3093fc" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string80 = "eb3942820fe42a74498278ea17038712f1aad0e37d2ff939b71d55cfe3bf262f" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string81 = "ec38d2205220614ff7a5d76311a5661851da7442734adf67df1890ff80fa7e51" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string82 = "f5fe991e9809b076b41cbda446dda964392f3666a86b87cdb8bf4c8be90040ba" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string83 = "f680df97c02b27fad2add251018194bffa1c47c765cb6c87a79ad07294bb0551" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string84 = "f7845353ef571f06a7adcee718b59370c3f8717cfebe76fe1bbc08c59ab677eb" nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string85 = "fb4983dc113b5fa5802639a9165564afa619e5c68997e62da4ce227ae7694700" nocase ascii wide

    condition:
        any of them
}
