rule chisel
{
    meta:
        description = "Detection patterns for the tool 'chisel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chisel"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string1 = " install chisel" nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string2 = /\/chisel\.exe/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string3 = /\/chisel\.git/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string4 = "/chisel/client/"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string5 = "/chisel/server/"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string6 = "/chisel@latest"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string7 = "/chisel-darwin_amd64"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string8 = "/chisel-freebsd" nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string9 = "/chisel-linux_"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string10 = "/chisel-master" nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string11 = "/chisel-windows_amd6" nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string12 = /\\chisel\.exe/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string13 = /\\chisel\\client\\/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string14 = /\\chisel\\server\\/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string15 = /\\chisel\-master/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string16 = "00393218120b164c3069439284c49edd5a99be83482ed9149ce9af0e8026e61a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string17 = "004b28244f398a619fe7d668f5ab925210e8a720c82344ae2f5acefaff30672f"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string18 = "0162e0e84eafc8ad462d99ab698da4deb9d8363a5c02a5624b3dc3640ebd3e21"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string19 = "01c8974109c2a3e134f3dfbdd01e0cb277b41d9aee313f33ddec6bb6157e8f84"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string20 = "01dc5af0ad49e564af57a8debc4b3c354fdcd3f85b36e9f5b5511bd674b98dce"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string21 = "020e1dde294fabdc174cfec3d2405f70d462a897241582d16aff6670230acc45"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string22 = "0235a4141278cb9aa45413f9ed58f0c20ae38dbae48b8440a1b96e4544e6857f"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string23 = "0253413ed641b86b351fc3b9355715f7d62c74bc1d954dd0c9cff13693535a82"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string24 = "0257fba1e0ecd10af76bf252a76f03656f194bb2173f8555dabd86a03c7df621"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string25 = "030cc05376c7c249583648d5324f8d2bad47ea9af1a4f1a751a09db700eb5817"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string26 = "030d5d76052e0da4488b216db816fd13bdaf25e047f0b34820a2b55305f9fd8c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string27 = "0313676f45763c5b4e90928b7f9d357253db656f86f8326420f51bbb9fde9238"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string28 = "0322cddf469dfbc17a818a30fb9eb4704a7217a62a8e5f7dc45ab3c89ab7dffe"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string29 = "0461e84f847489e8968b011128b6be6b001f487ae75b2a0c14ff6d4eafc9f2df"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string30 = "04628de68152672ff3ddfb372e1daa31b2f124ac79f98f245913522da3675468"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string31 = "04991e2f282b817df64efc7d76e57068f36993903e59c03acf05286cddbb75ff"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string32 = "04d10bef7b5d5a3c16782bc908ec5ea1ceacf33588c12d65ee4d314f6133d0f7"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string33 = "05f5eabab4a5f65f2bb08d967d6af41247465af213f1c874ad0e059c0a3ebedc"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string34 = "06a73e3d9717d7eb479c272ec005cef62ceb617735d4551fdaeab8a695abd7a5"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string35 = "06b7c041c6fb84a9b88ea99497787b0812e888e3591e71df3493180cfc1191fd"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string36 = "06c177a58759cb2d8947e425086a1d945d252c411c649121c5ec1bb795452b34"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string37 = "08349c406f6b963930b5ad1ec36e2f5f3b42fb5e3bbd887fabb8ab039592e157"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string38 = "087fc2c7df1f06a75caf0a25c448736b649aba88d37f2179e01dca89e16a35fd"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string39 = "089b8bdbe138301d16cce615880632cd2b211b9f20b31d4748f88851bd13a79a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string40 = "08e4c0ff7e4631b54fc848a95a15be134089e2422cc173f96ae11ee3e803d95d"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string41 = "09387bf7e4ca97704227fb00618e4056be0852acd1885841da239162457542d4"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string42 = "09d3cc04fe795a9883abe23bee0ba2b011a4ed759e09dffd811f157233688be4"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string43 = "09e9c1c8da3f14a7910538675ac43764e07fc91c15df116519059a1af942d902"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string44 = "0a3659cf00c99f85805b64bdbde13f3f3993163c0eaa5a6345e301c4331fb581"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string45 = "0c649fe30b4986eff17b3913a02a89728126d530298659f1fe1ea07570428c2b"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string46 = "0cd6b6f2c8164d440a118eb546a05d54232cedd792b4e5998cd653a5f3921a40"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string47 = "0d1a410e8085517a23da9fee226564169f767570993dcbb8f0b81b579a50e541"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string48 = "0d6730ca52c1a887006e318a677aa70ed059c67c4bb82af56fec792b2a72e1c9"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string49 = "0e34604b09472922b088573ae7b8a2686982b05900251f861912e3d9d2760980"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string50 = "0e744d477bb40e89af274ecf70c339b9674699e4bfe984b5dd73a2b877369d48"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string51 = "0ea533dd75837182416f5ffa7f51a36d82c407587068d0404c177f18709ffa63"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string52 = "0f84fb1ee028a12de7b7dfd282528b61ee8f248d8f4a6ea1ba8ea186dc0a06a0"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string53 = "1029c62bf37caa9d15ae9a74c931cb9246d5c3ce33be94a0eb8e282b6249c9d8"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string54 = "10e8116f55fa82a8b6517d2b8b2534744ef8477891d7999711dfdaf4a2297d4d"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string55 = "11cc4ad77bf6c0db1f6b3f8b85ae6ee230c3ca7e1425b63b7c1fe1b51c53b048"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string56 = "128038cf630fced3b39cb074030f57e07cf1e975bc374ff7e281cce382284264"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string57 = "13118127bd6a7dfaf76cb35833325627d1df6937064f6ec7d3a05f5829902d2b"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string58 = "135af50a105b966d85fc745bdac0b918c1afa0c1a7d4bbaf66acbc89eb59172a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string59 = "143ec041216db8df445e02dbb3a71e1603ab495879f073f63857474e32d239b4"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string60 = "1464a0e12ee6eacddcc2bc879ad601918412b0d64f3cdceb04c216d6a5485052"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string61 = "1487de57ec8a5a8201abe0b868c17ff8cf04bed18a298050edb663a793c0e030"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string62 = "14ed05af8630a01f953eee94967bf1e6a322819bf404b451038f8aacbde5569b"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string63 = "15fc3df52f81c0f09a430e52a2612d1a999284eeb802c8cec48d135fc3b46414"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string64 = "17942ccf0a175f0f4d58db7bc010d0c19c18250e1b634f2aba8d91ba6339d829"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string65 = "17ed9f14af38a0b8442ea9306ba6746746a3d18c2a45ff1647603a95bd4425c8"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string66 = "181de17b8aa7917df5d9e610cf2b183d92d84ec9fe4b809303842bd47022e49c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string67 = "184c81c9d2a54ae16baadb6f6523e4ae2060c6570682a721f3d977dccfd68a64"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string68 = "1868f166b2b622a3fd8bcb7003527e32700d222d5a8275da4479d04ec991e54c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string69 = "18c0331dcef2f8c9772d3581efcb54f2178ad7f48ee0a1839c987033cba5148b"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string70 = "18df81cab86972d172750f478678ab9bd41fe6c5a7df21d2d50d06bad60278ed"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string71 = "19188a4c5110709fe0277421eab563bf4d738cdd3766a440e76ff00cd653dc88"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string72 = "1a661c04442e03afed5683e5d92798b9be628e197ba047ac45b7d831444fc3fe"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string73 = "1b4874bdc2c7947b4ff389e6f408f10b44376bff4d5404040a4b01fdacfe2dec"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string74 = "1c008a8214c1fa6b06500d92a76900314b9f889818d6dae55f274f3a95d874b6"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string75 = "1c841d5d1d34538febdda50a60f9e4f7a9df773a40dccacbd6aaa75595babfdb"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string76 = "1d267caeb15c945b29b8a7c377582036ac1f72e2a977042947f149f099b5ffcb"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string77 = "1da68fc3d86dc4d5d67359180fbeb8ad68ae90e347d1a9c12f77e21959c25efa"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string78 = "1e4ff3139bfa4a040ce59f0efd10cca01d0c7da4e56c306b42f5e485b1a663e9"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string79 = "1ecc20b0a11a89389b677aceccc9a47b518aaf088c5d6cac63302b27ad12b364"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string80 = "1f38f5c7634978f31ac73800ad48c548b97dce8a7264d15fd5d2d9dea9d8416f"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string81 = "1fc97740da37d89c33dc2f6aef5840827cf0efc69519c320678494f369bac74c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string82 = "20792cb4150c6f086ad7c096ccf60c8213c2e68877caa7106abb62ad8a50529a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string83 = "208106c83c543b4b6f32f21049b2ddd4927c310fde1a5a6caf9707dd47289037"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string84 = "208cbef97b76474b1f24ca20f078a5e2077c50a5239c97aa332a297bd3f056e7"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string85 = "208d9e93e6dcf6d31df62abcaf50dceeaaccbc174496d495de8f4bb066c2547a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string86 = "214f24f7b1a2627400c2bbc78c054d1dfc7e4e25640b37a02ad76f0603184e25"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string87 = "227f0eeb2991708692c78418ff7e45562670a00f6a72a4157adcc28d5f2f5b4f"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string88 = "22bb4f8fe6d57072e57342b605ec5ad9e08c4489c3b6849f2928bdf7ea23ca45"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string89 = "247f15b5f3b38c9cf825f0df792e38e68fe4d69a72d21f596b9b73f570408278"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string90 = "2553a72abc7f19fbd345e3e85fd73aa883d062e893ed4f7b47ffd7648c16a063"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string91 = "25564409a011c563e9623b376593512115515704a5ed932dd18c20a040c8640c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string92 = "25861c1cc31e530c5f8162e78585f40697c28164fd3c561d3d1a31442ee1ec17"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string93 = "26e511920655fd8129d9d192f9ab2801a23c379bd4690bc1d71b5b94a9e99310"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string94 = "2796d1c48d81be1ec426e9c09cbffede41df1a6e4fdb337f999b6a62d5e05b91"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string95 = "287f0bded23d895ed013d7d66f062560b983f1ed8881d59e0ab7e9374bd76c73"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string96 = "28d2ed9659825ef2b0d27409423ead074c9fb88f28b2186a79bf0f849beee0f1"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string97 = "2a1482c944f5e27e23b23040a60c2dcebe263d1b3d071fbbea363707306733a6"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string98 = "2df9eb9a967a029221346b322e7861e6db914770fadb7e99fe98d4a37764d441"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string99 = "2e0515d20feeb3a1d5f368c85eaad188eb96d4beec0b38502413f5f7086e5857"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string100 = "2e10ef23421a10e19aa4d8093f3a283e7e3e638e16689b329850e262390192c3"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string101 = "2fd99d56b4565653d6d39f1bd747dd14d24aa4d5882dc237da165974791b513c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string102 = "3178ccb34c7dfd53d77a18d891bdc3d6376f5346746d65e6d386cc9c36040c39"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string103 = "3180a45a681653c3413afb788680f02754995a734bef851661056683691920e8"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string104 = "3204ad88f0f16fc276bde17e0cdb9c0144789b711e86da88599d193db09ce380"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string105 = "320fff4e8283c563cb74e5dc61fd68e4cb2743da27aae20d2b260c6c27e41f00"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string106 = "32d7996430dea9678208a61548f252f111eea644b325f9a7c2d1bce89e1cbf90"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string107 = "33323e73135262eaea63742b1c638a42fd535238c2bf2e6baa1b42fb593b0ddd"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string108 = "33ff6cd5604aa7d47c048e328546a890a4e5eb1cbbb578aeb78c41454d449212"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string109 = "3404870416355a3fb4bf2d43695606b77785e6fbf534f2f6a536861ffcc9de81"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string110 = "3461b057cfdf4259e44f40a0ad4490da3dd8ec511048f9eeac3dd224284a72d0"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string111 = "356fc0b7eacb629e745a774a22e5ed1f82aea70dc9bc420a1d71b9d28ef27830"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string112 = "357b50be2506c10d74d5792d52cfd892155540741f3dbf270eefcffe6884fd14"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string113 = "3688991da39646b2fb375ce860fc34e29341598abb35e10ddc9f4650460a1f2c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string114 = "36cbfc729051ef456ce4f71973619ce33c05ef4c3072a6cdf4e1ff555ab5a231"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string115 = "375b4f81c0ce1ab360c6f369c4bb2765ba3d683aae1f33250bdd1d1a79f9d31d"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string116 = "389081eec49334d1d6ef3ba46e2167f6f3010443cf39a4f2e431b274fb58c369"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string117 = "395408bc1ac0cbe250b3131c09592f7ac490a77a2625ce2f213480a96fcc8bd4"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string118 = "3cf09d5b03a365d25d2283bfdc5aabda01ae9a6e24147312bcef9b741e25df26"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string119 = "3da9c10c87a3f8b9964462299ea2edd92c3b82ed00e412e36a7a4a854b76079c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string120 = "3daf3c3717e738b47246b5fb7106b8b62e374ffc79a1f824eb5aaaec2fbdc27c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string121 = "3e3e74bdc2c23c8b8e6d177588d7d4d371f63b10aec638126c8ecb117579ba11"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string122 = "3e6db66b8d4aecf07f084a1fe53d66d437b800fe773476154c78df0c78d1e6a2"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string123 = "3e93d23c966b89a3e15719d482d61cb107eb12085cbace1a6453286decea13c1"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string124 = "3f70ddcfdf1308b16a0951689520f74df87bc472cccd2e7b2ca1316b4d2b0a3a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string125 = "3f7d06db3e6284ecccd59011f4a1c59c3cbf61804152948f54df02da5400f194"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string126 = "3f9957546691a7b74cb1670cb39df0a00d0e6b8e55d6a049278ce97637b2e689"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string127 = "4070bbd80f416e04985826ef55eb76bef5aedfd6abf344ce25c5e7762e9d5ddc"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string128 = "40f072d74c6fa0c3e9974ca3e7ab5fdafa63487c4ace88c0ec7f539d7b79bfec"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string129 = "40f237f59a3908d8ba89cdef811ea08cda8cfde555335efc5aa595bbbbaa2463"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string130 = "418c8a25e997241471590accb65f6e6727cd6f62d05f11c2a3b3b9667e39383b"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string131 = "42751e43f472016665ac6fcccaae068dbbacd836665b11b187c025e45da439d2"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string132 = "42d93b315b6016a420d76e3b99e46a1baa57636d30b26bc4c556a0c3b3d70a6b"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string133 = "42e93d295e08ea6af4885814b8cf66d43a875be0ee5b8966b5685e3e5269efb6"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string134 = "4328364d7fbb9555b5602f2c980475917bc34f73e6839da366d52a277715c37e"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string135 = "440fb40172430f771a7c289ebb8257988624fdd0a95f84d0b24432a18144b4be"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string136 = "444bb9e867be655f6c5c89b8f6f1d991417f13eeb2e1838bb42c0ac9ee5f00f7"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string137 = "4672ac01c62257129756f1d9f0ae1fd2471de6f78e47fa906af47e22204d917b"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string138 = "46db2ff1d405f57e52377c5e42b9918d7b00c47ea75a5a77352dacd1d8d0c97a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string139 = "46fd93a2992e8e9a29740d3d116d6d802315e51753f667cd3e462845ddea663c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string140 = "47eb5cfc14028872dab22f2202be7f5df00288463ca798191286ddb99bf7b34f"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string141 = "48736ecb605040b194fb7064d4bb621c38713fd3555a4f09f759ee45e81a2103"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string142 = "48caf6ffe4985e7541b9d34e8b6946d8c99e9d87cb46d146c81029fa280c03ba"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string143 = "49cf02eb8f76329b62378b8e9b0ae5abbe0312b9f2c3e068dbdf57f9474dfd8c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string144 = "4a4dbfa07c6f4a72b6727c4a2ed8ef2899f61f724a9b5d142ab30b1c283a6db8"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string145 = "4ab0e8086598b7691fd17afbfa4a1cd79b3a13a9001a791c15a9f30afd43d13e"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string146 = "4c069fe55bd14ff52667766cd057196992b0275c78a2d8d7139b7d57c90234fa"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string147 = "4c9c4d9df645d45510841d2edd07bd156bbb7ecd268626895f9b4d5ac8483633"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string148 = "4eb354e4fa6a349133460b511bbe2dab2afe57ef6d05ef0ae40c91627d17b18c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string149 = "4ec5213f3a8aed7bd1daac07c9d50932edea9384e19a215525b963427c25066d"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string150 = "4ff61cccbdf23cddf5699b2499468ed368967fc90f0eee241679c07c561ad2d8"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string151 = "503cf7c6f7afe5c03e8ed9bffa0b3b13443f1224e37b889e7add4c0dfe747322"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string152 = "50ba0bde643b62f3ddba44820ca5a45e5f7d45bf5305016150cfa4af7ab679e5"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string153 = "518357a490ef4696125573bbeaa2d541f7733623b26e666da70bb16ffeafd8ed"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string154 = "51b6b45c74aa811864e33ce5c7717018a688a81e53dd71e52379fecf9b85eeff"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string155 = "53153e63147a9924b06f0291a080ae86c692565a305e84f442b6b0a83f6a74c9"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string156 = "534cd20e815e2f733e1d381d60b80cbdffa476ca72d16769ad4e080e7f26a803"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string157 = "542bee76ffdd8095a8d134b6eea2fa001c4af43c1e6cd4e296c2b8d52571c16c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string158 = "54db0c7311eba1f9c32da2b1d0b9401117493a9b8bd58814e1cdb62239151204"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string159 = "550168d7c4f722b95288f8402f9ac3422dbbae250a3f36e3a10a985ac7f1c84a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string160 = "55096accdcb71eb43edd3001d4f6ec9c40ea88d448ba9d845782ff8e70df2fb3"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string161 = "55abc5a3fcc9e06b848f9d81d93ed2771947d01491f99ef3f55556f5b2a183ef"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string162 = "564967ff2524b78c74c3a7d3b31fd7bdc0750c6c478fb15c571fe7fdc82e31a2"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string163 = "5738fd3f47fb386d8cf45ff598545140f51b3b6507fa549dafc43c51dd27488f"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string164 = "5859e420b588764f0d8d5e301439af524ef486d1d39b0a189d93546cacf51d7d"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string165 = "5a145c3bcbe90fdd067206d68009d5ba36f8d0bea8f1d6bcbf0a0f05005edf38"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string166 = "5a89f9df7621ef8eac8832f7397c55559d71cee04a798474683e7e0019f5ee49"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string167 = "5b4300844bcd004ff1d5415a81dde48c9b3505338e8ff1b8bdaeb5f89c415b46"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string168 = "5e68b0a2d0424b4afb739ac7938e49ec2e9cb41999346aee22c0284aa1cdcf5c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string169 = "5e6cfa7f3d2e7bf2eadb2d4f197189d43798b3270c39bbe3a2fb99c5684ec686"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string170 = "5faa6197612a38b41bb54cbec6c782b5ea1bfb2da9ce236e493451de1b33ff47"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string171 = "5fbee690299d3b057447b595c46845c34a1fe90a1e616fbb07bb5e0d019bc101"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string172 = "5feea3420bc6019eda4db16b0c89d205ad258d54313782f236aacbf073bd33fa"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string173 = "5ff663f155004fde14399555c5327e3a67f277574c115cea507ee2998746bd2d"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string174 = "631cdab8f10610656a3f360d18fc7019549a68806579092a83cfdee543a38255"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string175 = "63839def4c061f214718a67dc487187d5b73288d72845c4007b5162ad57dd47b"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string176 = "63f5ce1c0d7cacc9f68421eb56b0640a48fd52695fefbe3589d7a2520a684123"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string177 = "63f6929cf8f9c534611dc567df4e773bc6172288d3c6edcb3f92a09e303ca8d6"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string178 = "64293e56dfaad772c31a8d53e7ea876b9db7aaea29e89381684f56227952813a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string179 = "651095e7885df539f9cf20ded168c9097051bc99bcaa5cb5442d21267e14317e"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string180 = "65ed54763a97588f5ace7c38d2cdbcf925dd65f2d5fb3ca1548b23c7efb54efd"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string181 = "6634da3e8e2590317704a1ddcba7fcc177aa5f532d81717431d0a6668d9594c8"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string182 = "665593018e2d7938198172532fad4e17c501253b1a75106904d0eb50bf2b8c75"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string183 = "67681fc7c1c0d06af7eedea1eb1f1d04e2f7f34f47e1ce3ceca7e4b93e318ceb"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string184 = "68af509fd4c4e58e7cc291316b72dacc5bf2861340ac83da5fc1287a38f0e615"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string185 = "68cfcef00c7be228c8c10ec35874bbbf3e3a6eec33ce3c2697af0aa8bcf844d3"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string186 = "6a956fdb1b7c65755156898c2f4065a555eb80393a25dc8b1a118f87e67d8368"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string187 = "6c0f535128c8536421e213c4c1f55e4eaf690aaca78e34dc106994df1b48cf4b"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string188 = "6ce5031943a475616dac98d91e84196abd59c8067542c442e995a0d5e46f89c2"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string189 = "6cf8e628d3c3c765a55d482e7124e88f59a47949c8f677ba45b00aa0bbc7fd1a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string190 = "6da346eecac1a1bb11f834be0ef0b08539fb0f9ec7d8cc415ae9e301f53a536e"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string191 = "6e1611b4524f7426cbd8d7351b269a1239ee710e575e9e460fce110c35962de6"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string192 = "6eabbccdf8fe27c93e5a87899fd2ef81bf1670ab65103b999559266d936acea3"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string193 = "6ef5c10715019e5032c7cbb7c51d6e6bec069098ce76a1f83e7c45f250663f06"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string194 = "6f305cfc78d9cc8ee0bdfe2b55d4469824a61d1ca519e1456bd0257f7decb48e"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string195 = "6f813ccfd911c1512b7bac17e0c0634e9953b9626fcb0f7db3ce4208578d6190"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string196 = "6f8aeb6d268e81855ae004d52d76c046bc092cb9291f6277d3c317c1df712fea"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string197 = "6fc368328ce3a6d164f9a867b1b163bd2aac732b49ecda43a926ff39dc81e736"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string198 = "7015bb3d9a25c8809d80adc80aa0bd7e89c04502ca2b4836fcc62312d167a977"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string199 = "704a31cd89911a0f7d1741ee9ca32ca0f5496b06370bf398dfc5b7d3a31ef563"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string200 = "70cbfdb9e353bae5fd131519b3258be7c9f46e60d97737dfcd386e2c0b61ebf5"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string201 = "70ddb33c1ce8b8ac5d3a7339ed37fedf436f91e5a31bdd19c8029968766ad3e6"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string202 = "7116f92ef4bdbb61fe15e5158197c984bd61ea944d95a854f30e58b19db43dc1"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string203 = "716066f05bcc12159c8f0d16846f924b928c75cbae2eb36f9b96b2d8f770cb54"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string204 = "71f693cce010e95145ada158a6ec7e7b1b9902f222dc53d9d54bee4d75031951"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string205 = "73510d6bd5ae0d698d510c6ed240d7e5cefd0a2111a3123ff68ef63329bafece"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string206 = "73746146beb936f2c5fc328293b12683e1e893ba74f7c9f931a0e9fe1ab2d254"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string207 = "7504dee72e18b91d0f759f04385a968879699c228dae9c9a2c338dc7b76f3178"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string208 = "7531c23a8951439bfea1349ac6ad30a9bc5c1269718aaa7e320986a32cd05d30"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string209 = "763c42f5892b8c16de901e8a29343b863dc75bed587e2f4c9a22eb1b9e8809f2"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string210 = "7654bca1fed2114ef8e78d51ef5dfccb2ccb73e51ae0dc65f4823b33457a3b40"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string211 = "76c30e2ea86c1c11238c23cc8e6e88ed76cfd666832df7af587036d20a1e98b5"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string212 = "77de77149c63a656601bc3d0f4c2704ca8e22673abfb1d235e4f45d5e5befb56"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string213 = "78b372bf29a88ec2683f975ab11a728a53a19dba021023d9b2ee46fb94cf3a66"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string214 = "78fb6b3b97fe4c42400a477e013f1f848a5ccec7d4cf51d7087faf0583ad491e"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string215 = "793f49ad93a26d3c9407ac76af0a8785610db3216cc96b348f6417c2e3583575"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string216 = "7a324791d74e0a99c63686f9e2cd5be616286fbd19b74f780de251e3d8ab87a7"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string217 = "7a6b32cadac1e4193540c181b169ce4e73dc69a5bb185b9e98842a4e4205cc81"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string218 = "7ac42abfb232c1b9f235969fcebf54bad0078e724552cdd89b5f32805b77a4ef"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string219 = "7acbf2c647d3fd9b61f6c3c8cdc8bcd3afd9f4dd1c2a95a3b30dde583b95ed22"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string220 = "7b1aa993de7f49a7731c952cf3abedad501f45dc378e18b9b8245eaba78e72c5"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string221 = "7b206d4ff0ebe922b4242b4821c84f9e5c05579fdc4c43033ae9a45f6494cac9"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string222 = "7b5930fe71b9746fe6fd52455d84ddbc740d1730be6028473ed501058f0f393d"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string223 = "7b70c0af1d1d20eb090e2fad0afceef71e12b1083956dd7d58b181425478b764"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string224 = "7db43d94124a60b25347cddbba96109399cba1df3d4b7231d032888e4c2ae061"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string225 = "7fa9f247b1b89382e6eedc622dbd5951f088cfff0dc517f3c7f0bb4519c30e7c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string226 = "8009852738404fcfead7a80baac530fe2a8633d4dcdc17cb9230fa69b026a72b"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string227 = "805d62d6cb854199c313f9724cf44a1ec63e8d35b9de235f529cd562fba6011d"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string228 = "81da530e620cf0c86a3b6a99d562e7c175951d9417264be1dab397c4146814ab"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string229 = "8215225624132cd5a3c16699071178bea0fc91cd6195f67d1a5e8094142dcfe1"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string230 = "84008e4aef450b5bab0d589b59174fa9633820448d167bae94b00fe5f62d788c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string231 = "8405dcb456eb56be5a810d5189996286ccf9da781705ac1788644cf91487ee8b"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string232 = "84e1091e97d33b0b8ae7c600f649e0cbaf00c1b7650d965ba4ef903eee709550"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string233 = "84fca6c04d81477223b295838e3edb59744fc564c68c614b93c33a537a066bd6"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string234 = "8524836909172fcdcfc6c1e805d775bdf84a499113a645d2fce7797d89af6dc7"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string235 = "8574d9733f8ab02facc74b6b2e51a5a0f4eb5c370e005de4987586cb53b52314"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string236 = "8744313fbf925e7dc5aada01fa6b89589bdac85546a51c766fe51b763c984487"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string237 = "886c0eac43136acee5b85b22c72965d63faf9b9f70ed28deca9c3b028b22dee8"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string238 = "88babbe96838fcad9b486bd36f4bce32d242848ab4aa71c739fd6338dea37a68"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string239 = "89873326f393acc1d9c4ff7d897f60db68075d418a034c377a2d72cd1a09c95b"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string240 = "8a5d969cab714560a2c7109d7a70bf653d860b846929d2db55782f4ec2604597"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string241 = "8b3dc5f7f95e60cc22e2e41bf2c000c3ab16983493bae2427b92f984147de598"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string242 = "8cb79a0a047793ff81319d7e4999732f8fcc49fbb2ba76f9ac38abf988c3eed8"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string243 = "8ccc989ac8dfc5453a486361a7850f1add7e2f7dfe4016840671e8c183ed887a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string244 = "8d87231f69d0fdeb63b10141cba62e31cc0fb16a105fda66fbd77f06e9d98feb"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string245 = "8dca31ac3cffeacb63b9f572bb9f4b53481e51d1d74269168834c395725f0b6e"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string246 = "8e81fd470bb1b6091600ba95f951405e35c9ee980ef34dbe6525a5aa0a672448"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string247 = "8f31909ad50984539183ebd099eceed04617e520d44c8ef0081a114aa8d5ed01"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string248 = "90023e0492635199b386d05e8bffdb806f0cc6a6d0e6a2dbc9a58867d002b566"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string249 = "9037b5197eeeb068f24a73f9ac99320e0aeed9a91a69f18eec013c689be871bb"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string250 = "903d7db4500738baf1e30f3923909fda0df637ca2fd904a6e67565f72925f613"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string251 = "90c08dc1a2ec6ad65002990fe43220d8974c92a02c2639562447c98bdbc04a22"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string252 = "90e2d1bb612d9658067799266605dff148b292dafd4f6ddff3e184a9b7998376"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string253 = "90fcf63af14fcaee770bbf4f777845b46fc81a6c38ed966bb80c7b5078d46f17"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string254 = "91474981006a8437b1f628985dfc79c56dac4cb73dbcbebed1c01211149aef81"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string255 = "919282a2110d48cdca526f1638e723c84c3f3a3d85525488887b065b476b3887"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string256 = "92c2dcbc529e4f81c4bc9aedfabc4361314ab0799a3fa56bc14750933cf207a3"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string257 = "934cdd2196c8892b2587ae94b5ae02e3c51ebf73c4c91b43b081d8add9ea381a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string258 = "93bd4c92a4470333efab88a00bfec4c3fc64318fc8ce0ffb9187ea54a9acf243"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string259 = "978dbbb6bf4794203430805e3cfe01ae52b0bed20f4c4c88d7117ecf6b6a138a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string260 = "97c42a422ddd966681ffad0b5bae3df1203f52b11c5be3a14bcdd76366c1f369"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string261 = "985976339729a11396ed9c207afa49b16961aef42db3ee69066d2d2a5c69bfde"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string262 = "987d8536a5a920ff49ab1d0948bc5d7c45a7610b2737e407971c361d7072485a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string263 = "99164a220ff13f15d76096ec91b472b2ed8fd5670491f5baf073158b92e11374"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string264 = "992bbf36c83f56d459a79cd34638f7ba932ad4a313eb9a63c8a8cf111ef9497b"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string265 = "9941d3f3192d927be91b38a3d13e40aebe91768185bc237ef798ae20f78dd952"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string266 = "99ac2e0be445506852788ae9ed8f2deaecd39da027818c4530206ca9695e2002"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string267 = "99b151997a57f29a3e3436bb4ebbe4357219ae0694a9ae6561afa2da568a0768"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string268 = "99d336f5850bb8ce58273fb3cc8f5e2724769c0ff982601c16569e74da42da52"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string269 = "9a0281a17a7ed9d95de46360406707d3b6ad20af4e3826726cc0f6a70e4496ab"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string270 = "9b0a4d1b72901510834789ba7c2a8bc8806c84b5cb06b29db4aba208a0e26654"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string271 = "9b0c3ab3b24b993410578c961a370a1ca59fc5685a9888596fae81f65eed7d8a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string272 = "9b77b2d26cc5e1764b87af4178b3b5b35338aab8df80e5f311a10fbadec119f5"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string273 = "9baeebed17f1945b5680bdf630cbe15de32826aa2f402d23df0a991ae73a2235"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string274 = "9c4fb7421bff7098ad6cb75b882d76306305d1741abd89d5767c4f7d7f523a62"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string275 = "9cb46943dab29908a33b801ec3c2033f7878f19e0ee2f892cd6d0c0db6bdbaa5"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string276 = "9eafa0b3e8005c6b03cb5d2522140021c573b5efd042fcc057a4ff75794c28ea"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string277 = "9f19635e335acf9c73acaa6754d100215f3a14a5dfb656abf9dd416237dd3b21"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string278 = "a0520b0aa5b53fc9f4f2257be26377776ed65ad998a2b515e62b28a8065554f3"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string279 = "a0c0fba4ea509e8ff5ec12e60299e0d08f83dcdd5edd5ceb10d18fc3af5d830b"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string280 = "a0f8f1ce4928854b11afe7fdc17cf5a932cecb00ddc626e5b9377c5de260cad2"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string281 = "a172c88c5af8e591bd8aa539973f62f242b368157ea187d9dbfee8616b51d5c1"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string282 = "a2c2db4fb0e2ec86fbdda64d1fdf5a084d036073ffd366c1c56336c4c5c95bf1"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string283 = "a3546da8bf7e18eb991cf72b2d702c6b07997140959f9ef56ba64b2673bbd7fd"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string284 = "a4e7e725eb3998e5dadef0f903eb5e5f3e2b879876b239a891de5f95ecb2c1c4"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string285 = "a5323adc6557587f17fc2766b95efbf76e5148dbc14b744cbf72b40bdc40f601"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string286 = "a63a403167d39341c7a116a1f8d599d19859743cbb254ba6203733213081913f"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string287 = "a63e1dbd23bbc640410dd811ab84e179b741080c4b4d8b5e08e5622d79884e38"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string288 = "a6f37544d43d1d50d3a860e72e723079bb1fc7f7e956089cade9b41d1a585c2f"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string289 = "a7fbaa609d657e8148a05586684aa41941b28bb5130b8db24b091cf0d9e2ae79"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string290 = "a8459e2fc93dc20b5277e4f671f612b96b2b79ba16fd31b8e98e847cd7f3e7ee"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string291 = "a8ce36f599c838c95b169252fe56cd412923d8d25f1cf906213d39582299ade7"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string292 = "a91b2af5590034ad95974a084b37d629d53800e8a4317a54080588cd8504c98a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string293 = "a96b774c3d3e7a7727bd9929fb18fbee592377fa1bcd9a732bb8825bb0456357"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string294 = "a9f7d67e29c2b7f2059636c73945b9946185a235dfb12e346e07eb7b0650f714"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string295 = "ab2c2fad05bea1ece5e7585409c3263dcd14eab456faee47bc9f8a3b866326f1"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string296 = "ab9f2bf9d733a41af5323b5cabe31812d43eef41cb6dcfea9ac47308c91428e3"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string297 = "abfd0a70ecabaaa68a9f51b548542577c3859268b352c92cb7d9fa1caf6c3168"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string298 = "ac0a36687a87166b27a9d2f4c041e5131b3aca69ab811086591117bd7f3b7eb3"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string299 = "acb2c4419a7aa4cb0b812a179bdd51d579c0cc1f193b1b8911d64b2d3ff8f450"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string300 = "ad1e96ef3defc771763f6f6475dc020d543b9712d067aa63ab95ad56a934c5fd"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string301 = "ae04b0978a3e8179a0d2c1cd4a78fcb58fd1c3e8d5984ec1d8e9aa0881702676"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string302 = "afd8bd5606cb0e36a8be84a629f7fda4b4ada793ddf9eb758d9259e529f9a76d"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string303 = "b08782b58eb043e7cd649302ceea993582f55762d7b384c418253d227930fe32"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string304 = "b0d2dbeadcaced10cbffe3bffe6419e8f64ed772ae68698db3d03d03ee5f92eb"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string305 = "b0ef1323e8a932c4ce1ff333d0ddf165c87997f07be51453adec35360feeb451"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string306 = "b1d9a3c0bd0e7b091ac0dd51fc64ea57f119146fb767a83547b8e95ef2ae5f67"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string307 = "b23b05a5d904b794e12894c657e7a413a607f9c45bf78d59760cb4c0c21a7241"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string308 = "b28abc2701ee133be62eaec40bfb4afc7c3bd862e94aac529b6ea687c0442bbd"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string309 = "b3ba329c974ac0a0ba97b9b63c91f562e80324c8c95ca22d7f004391f51aa51d"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string310 = "b47e50a181795a89f5972e7a4c06bf93a81cb8b15fc173ffcb526bac16f71f09"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string311 = "b53fab9c9dfd6eabe8c543a8484f216dba733b3831b4c440cef8064407c343fb"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string312 = "b63d2ec8180679831dea14c5fe8f85018c196d5f38dde79ffcfa839f87729188"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string313 = "b6d7a37a1e42825a1e744a92fb5e39ada8ef3f71c494370b35b83c77ce06c344"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string314 = "b782285888ed48a94f495d3eaa46fe9f29f7bf087197c719792b6e730afb937b"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string315 = "b7e50a98223c9a3008aed3617b5b9282a40b7ef60fc274734d3970c7f9add804"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string316 = "b872e0bbe252aa4e33492453232f6320b8d35b536db2efbf9d50a1d4e5de14d7"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string317 = "b97aed185c60d0b6764cdcd4c6133d09c0f028ed4a53e766d75b42418765e0c4"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string318 = "ba933871cda9e4c84297af7c34424c01d565e7f3968f14e8bae4ec26e7f7b389"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string319 = "bb33277d1d07b2dc6438e1a95eb4446d1c7a975ec0e70bb8f4b09fe1160205cd"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string320 = "bc2ce508993e19027fb23f837dd48da400898cbc83d9adde6febb803e76817ed"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string321 = "bc5d95f4894db18e69826a772226989ca19ea7e63dbb9fa13775836a0b25cdb5"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string322 = "bcd23b279a6821e726d190afb11762f53741de0c8ee4724925a3c908e55725b5"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string323 = "bced4fc981001259eacc23145a5968deda2cfaf64db8e3ffebf2b6ae5bcda874"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string324 = "bda4e12386c2e02081373da1ac905a6fba42ecdb2310d06aa2dc6df8b71ef544"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string325 = "be03dfd28d37a8c444de321828edef417638c767a2a167133c5bf3a0b51ad60c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string326 = "be3ae8e7cd4138850830f1d0b40cb409160a4449dda205a325c95de7bd2b76b0"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string327 = "bed39aa210495c7abbcea21448c62a2ac5a90eaa4d6d3d315f2a09273279af90"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string328 = "bf7b774ef4abcd725e9d3a3ee569f83db21b2248056fcb3642099b005c089b6a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string329 = "c00b3bbcd7cf59063dfc9eae66351a40c7be586e61156347b8c61a8627d6cb72"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string330 = "c10ef39f9a2560b0f51982c8553c6fa1c3f4a6700f11796b3bea82f8b0f650b6"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string331 = "c209bedad717b0db49a7109c3b4dec90cfad5d58dbfe7e8c32f828c61494bc60"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string332 = "c25ff60d4286c239522b0b0292c801a5711ec994fa90429adf7d57ed8735bb07"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string333 = "c2c3bd47f27bb46be73e9ac8aff49dc36d6baea77ac7998d3668aef1b4893f85"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string334 = "c336fabf158958c6946e05e28320ce520adab0ee3ccc7e1bc616179d1ece1908"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string335 = "c33fcbfbaf33ff5ed81591bbb65211e30e274e0c25b04b41cd8640df384be036"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string336 = "c4c624294090555e88aff480bc19f55ffcd1b51dda2dbf55fe35dde60b374fd1"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string337 = "c59750dfe30a62ae41e8ba1fe138ce5bc575041afa2d7b87645e2f5d54526a9d"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string338 = "c6306acc18cfb5cd38d33896213d4b8ba1b5f3b42e55d9dd9678bab4cbd31d54"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string339 = "c654a7ea1dc15b2c30ddeeba64c1f1fb4e7f1f53cb858a7f78ce508e2b6f259a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string340 = "c7d0e470542ece3342535057e01e84b962b19959e5142aa61633f49ebaa52775"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string341 = "c821704956c03e7edc23f0eab92bb7ecb668cf34016c523101681c608645da67"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string342 = "c929214fbc050208831b18c088d33e0db1ffcd2f26103bc3a69b0081683db1c8"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string343 = "c92eaefade39fccf3a8926ae8b579333b37a58bc15e4c536eeb16b6bdb97f5c8"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string344 = "ca32913db657697990e77b687cfdd25a3d40c45169802c874738581d3408549f"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string345 = "cc4e23ea2383b1649d22a6bd176f8b27505919a61d2e838ad337743c32702de7"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string346 = "cce469f76bb65315222426a32f579c4ba820587173b4dffb7f012f5b0bd5a877"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string347 = "cd2101e2377fe9da558c198ff1d2311a9eeec08faa767a86ac51fffb50a5565d"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string348 = "cdb93e8cd015790f3895a76168b8ce42f73bc7da4ee4ab08c9ea7ae7fecbd9e3"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string349 = "ce4821d0b380319df17ce6166db15577abd9e77d090d15c83fa67545174f4631"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string350 = "cee1f314c34ecccd4fcb94d0715126130d02aeb153ec8504fbbae67c244cdb45"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string351 = "cfd8565cb10640aa0710735a30291d6edb24f6a99af3704eb6bf1a016e83564f"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string352 = "cff5798485f1f260bed03c9f82572288df0dfd169fe1e448708d229fa8112ac8"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string353 = "chisel -"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string354 = "chisel client -"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string355 = "chisel client http"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string356 = "chisel server -"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string357 = /chisel\.exe\sclient/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string358 = /chisel\.exe\sserver/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string359 = /chisel\.jpillora\.com/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string360 = /chisel_1.{0,1000}_darwin_.{0,1000}\.gz/
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string361 = /chisel_1.{0,1000}_linux_.{0,1000}\.gz/
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string362 = "chisel_linux_amd64"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string363 = /chisel_windows_amd64\.exe/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string364 = /chisel\-master\.zip/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string365 = "d1fb14a96b35b807b6b2315bc198b778f0ced472685c708d757a5219ae06bba1"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string366 = "d28b91e8fef0277673acca0c19b034b4bcfdbd730760714fe673b535282b5a01"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string367 = "d2f0e9bf854c80b08a355e367d8f8eefb6defc64c0c42e3a970bbd0aa9abfb8d"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string368 = "d3e8378618c05eab2159113af6737a1c6b49f982ebe2eb1ab7e9b52e5ce1b330"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string369 = "d4c38a6655fc0b8d8099d46fa13442101085a999199baaa0440068f2d3b982e0"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string370 = "d6b26f886ba34b221dca49d48e9c3795ff9dc43a5318113c2d269a116ef50b9c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string371 = "d7cfd598a2b8075da50af756bc164c272f247b69b1716b318b919f10cf0cfc8d"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string372 = "d7d5ed843d7c8543f15ad0b236d08c00c848c80480bae5f67083dae041ffcb67"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string373 = "d815672bd8c68dd861dac2266be662d32c22c7d07f13214ea84fd0cbd775ab92"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string374 = "db0db42180fbc1a5bc259234ec07d437986660e88545a49563f4f5ccb761c363"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string375 = "dbf5c14d8ea7fe326f57fbe2b2e140367d7cd6003cbab42bf4bf11de50b52359"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string376 = "dbf75975cedefebfbc67ebc49ea438821e8835a8ea6b4b922e473861cf72edf7"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string377 = "dc713dd00f6dd0dbf2edb9ec5db8749e996a665356e8c6d595b6558b8864b06a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string378 = "ded27a571bfbdf7f33a8582ba4d924604a825ed427c0e734d0b299328f2c544e"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string379 = "df32f865014710359e52fcf0ba175ad479fec41cde92dc8dc4b7524145121ceb"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string380 = "df660a53e3b5d5aeaab189dedd61587a2d1215ad808f444333f230719e715b8d"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string381 = "e022c33f7f02b564f42f4ae68edded719b3e4cfdb3ea9ce9de2d07dc1c586321"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string382 = "e1a5b167ec626fd934b6abac47d82987ba3313d505c1b3487072cca8ca9c4e65"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string383 = "e1ed358b0e31199ca8ae3cc4307183d3131c27cef32c610bcc955a03527057bb"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string384 = "e237f1a9a8fc58940811f2ea1eb987242718290c588fb36c29741176700980bb"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string385 = "e23efc384f4295bb8fbf5b0e6f2f3539f6ff45fbc2ef8ce2bb54aefebaa069e3"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string386 = "e2fc147f2ac14938a48eebc9292258af10edcc7ef057acd07ff2ae6729f1cb7a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string387 = "e3f64597d5022d8716f45ffe57fb9f5f25ff64f42b9b61a0a64cb4521a453ebc"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string388 = "e5139e7b40768b3a2a6be05138cd8c5cd5fc71eb60b108e0743077f0e4df3a4d"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string389 = "e614bcf1b052fd1faf384fea62ddc4365051cef7bced133d54cd972be74e550f"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string390 = "e6cab14548d77b0f7829ceb222c1b634432afd423dcbf61e160634096b82bce2"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string391 = "e6f1d80937b4c202ff8f79e77bfa5cbadc0a42975234f981b0b85dd7c8aa75cf"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string392 = "e8c42b6656710ed22955acf7a112ba19b6f4ccd8c6fd195f9133539eeb1aa692"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string393 = "e8e43ef253fac38fa05323b327609c182bb1b5342d340301424deeaf1bd26673"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string394 = "e9255f6726a695cab4ecf9d7ac34c1dd5dde9ac55a3289892a43ee7869e2a0f1"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string395 = "ea9f997ffb3dd610c9848af65ed980b348c06d8ee11b7fb670d6a789f8075c5a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string396 = "ecb8ca794b3659f7ecf353e6ae879a6e405bae62ebaeb69cc12d596915d0e0d9"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string397 = "ed696e567323b56a31408da5f6e12181ae0740bec1b23fc9be2817e51cf13235"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string398 = "ed994cff2f59eddf328e72a6060180b724d931cb9b564327b4a5eab28cb5cc8c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string399 = "edf46019fc966e2dfebe6209744075f41b8e58dcfe1d8247284e88b240149e35"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string400 = "ee6603f8abadc1b575b6c696caf487da5421ad772cf65b38f49c35630d34f09b"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string401 = "eea432f6f16df3514a6310b593ea8676d2330310d9181cda1e7c278ad53758b3"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string402 = "f19bd04ee2c9271e758bc21fc681f0a08ebf441a70b3221ccf5d201d5ae70f9b"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string403 = "f1a21c50b4c315780c16c0777f84b5fa407a98acc014cf68ff05e3c007ce2f0c"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string404 = "f205814e44353d23a5cef0e3cbfb37cc8ec4bfad9def53384d671dcc043c00ee"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string405 = "f2d93a4d4188a53285c334699b010750786a607162a498f2ff2a93d823cbf0fc"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string406 = "f5028addc30229d68561491b4609ddfe0b908547cf31af3b810177d14c95645b"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string407 = "f5cf5d30d16f2e4cd6deba19cbe539655e2d3c14002e47a35ef30ff6b795e5da"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string408 = "f6324f8d7b34cbf7dd27366148d1a9923219187ea46c4d5c029ed3e37afd47bf"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string409 = "f688df8c4a60bbb34467b8ef179a51f06af68b9861fa848d591df9c316a0c974"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string410 = "f6898381e46e3d7b755f69c7e5dff72800a29a37ea707ec06c3c793437910dd4"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string411 = "f6e0cfff7d80e0673848a96bc1e667c2716dec682c4f61156f83b070b9da8b4e"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string412 = "f6e25a72071f1dcfc6f383a694cd1a8c1889560593abf02b45451c6c7a851aca"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string413 = "f6e3f58333eee37bb52f603b1c8f9aa73d16ec2051f6349284d0f09c8847bb60"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string414 = "f7b0550a05c30a38b721f15f90e84f104a3f98e3e8db7af96e5a98e7b79ecc11"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string415 = "f841359414535455c39fc29a869f0d3f7e0299282699ece7a9d40389d921bba6"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string416 = "f89d5657f9c876889a0a1a0b5a7c599819d9cb731c529527af700c464b586bde"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string417 = "f91f2c86797c2b92c342f5a9617a14d5de59c05aa1bfeb50c32061789185d6bb"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string418 = "f9595881272cb6e11dcba5300706a44b2c8f6274313ce948d5f184ca973d0730"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string419 = "fa994debde4c3fc87853ccf7667ed991e2c77a21c3ddd54c024588372a96d831"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string420 = "fbbc07b9b6d448c80d5bb8a086d715631b78e30eb10cb850601317b21256fb8d"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string421 = "fc1ca88117a5a0328991e63be9340c949d22a25f53134d04c1ffc7be2ed69e6a"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string422 = "fc5d03fa8fedd73efabd7066cfc4bbeb4777788c8a88301a5a27011239c6f994"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string423 = "fd04fd7f9fcc43cca1aca5ec9050e6f7229decc563b2e31c8d0af385d425980e"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string424 = "fd8dddeb318eb9ccdeea441dfed3a0b01c1187e1b165b75e7aaf515142abb171"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string425 = "fe6f27e7f2f8b93fd436a7ec4e99c0e79b40e639772b5c8e378406c7b867bd63"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string426 = "jpillora/chisel"
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string427 = /\-local\=0\.0\.0\.0\:4001/
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string428 = "--name chisel -p "
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string429 = /\-remote\=127\.0\.0\.1\:3000/
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string430 = /\-server\=http\:\/\/127\.0\.0\.1\:4002/

    condition:
        any of them
}
