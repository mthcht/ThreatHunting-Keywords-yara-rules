rule gost
{
    meta:
        description = "Detection patterns for the tool 'gost' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gost"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string1 = /\sgost\.tar\.gz/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string2 = " gost/cmd/gost" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string3 = "\"gost installation completed!\"" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string4 = "/go-gost/core/" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string5 = /\/gost\.tar\.gz/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string6 = /\/gost\/raw\/master\/install\.sh/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string7 = /\/gost\/releases\/download\/.{0,100}\.tar\.gz/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string8 = /\\gost\.tar\.gz/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string9 = /\\gost\-windows\-386\.exe/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string10 = /\\gost\-windows\-amd64\.exe/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string11 = "0276ec0ea830a61275437a98b81224b95712ecac5a7b9850bcbf2444ff46e47a" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string12 = "02838437eb0acf23204585e8c21252b8bb9413dffbfcbfcd0ff9b05735a98ac1" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string13 = "02bacaa4ba2b64eb019f7b9da5861192bf0e85e4615a299035086decf9da7d06" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string14 = "047ab1af44f368297bf21b302a2548a556ca4e6c6b721940954e88f43d1cfba5" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string15 = "06dfa5d139637adf641c5ce926f88aef127165d305af64e655ebaf069c7e3691" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string16 = "078df1ee57a842cc2395869797ece90a7a6d7158090a84f8b78f41a3072505f6" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string17 = "0cfc3c9a964253eea12a9d5705ee0ca0967605483f1dca3c6ef28aed5fdc5b30" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string18 = "0d7f56e583575888e68ce8c945fbd4c05842dceb352ddc7e8beeb86fe0d36861" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string19 = "0e110e91b09baca32b4fd9e0a972162f36f2e6e7c58bf4ee142bcda7c3411c93" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string20 = "10168a998e30a4f0d0d175f1aa2d5a533df3d69cf206f04f7d2686afdbe0949f" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string21 = "110ec720cf51d05c3a07ee73534f4c949644920a4760f1ceb8fc09e80172aaf0" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string22 = "1296cb071a8524b29efc2c955fe2bffb4eaf545823e4dad698fb70344fc48074" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string23 = "146a734ad8082ac508f0a82c7655f3bfe205f5f19f6c57cbd46ad24ef5b24404" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string24 = "17eaa4e99dafe4b0cd9d250dccb2d2edb1c204922a58da7322926eb4cc2d6a70" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string25 = "1912f7bb54e7c5ca2f93c0302a8bb55df6bd4ed8489d92619cfbbe970bb0bd7f" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string26 = "1cd2acf92f240f2672bc390bdd1a0138eb0790732dca5c9f7e0d88f980ccc476" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string27 = "1d716a8d9312001b2e35f0e9081e4efd60c0204e5bc9ce5728a82d02218ba849" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string28 = "1da052796a987601ac6085ccbe6957104e3d56656be4b4cfcfbef4796ba8217b" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string29 = "1dc896f509482e7b6892dcd0e4f83cf5417be5f7a9edd1da5afc810f49ebeb6c" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string30 = "1ff7731d1b7af7110f27796e0fecb551cb5067030aa7d87e333d46f3f57f4214" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string31 = "20c52dac0196b6cad71bcb9f4796ca4db198465e5366345347f64acdcb5ede7a" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string32 = "254cc9b46f64f1ae8150c65632ce0e749dd894b20db9d39313e8030477152add" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string33 = "25dec6e071fbf271817fa34a76abe61e41e2cb27cc52f25d78488340ccedd190" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string34 = "2adf13d1d4585ea2efd72e3ffe5d6f9be0a553c66e3d171a0e13f18f7f05d375" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string35 = "2c344a29ed1d2107554b83137bdcd87db445be709b089520282945d21c755189" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string36 = "2c9ecb79edd7d06bfec0529052f8fcfc4c9c9add475baa9179f6f9e23c456326" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string37 = "2dfc1eeac50e3d783d124fa88c3072c2e475d6d95603b85d4774c37e37a76165" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string38 = "2e75b82c2b0c1f1c1d449fb6077cad9bb5311ed933f990214efdb6556b27017e" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string39 = "2e8bd529f1452a300c60d13e57b46c35d1c3c2f8b42a4b03ce82fbf78211af49" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string40 = "2ec1517476a6c8d3a524fba2461233a2f44f7fdc5ee8906aa7bead7514854cc7" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string41 = "2f36ff1ba8c834c8a47211ccd879acb37f75b1b34cc814c39728c7a190151c97" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string42 = "2f6d418d6b2a974433581cdb959f6b0f8f305fa48c00ad44dc19a9d7504a4c5f" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string43 = "2f6d418d6b2a974433581cdb959f6b0f8f305fa48c00ad44dc19a9d7504a4c5f" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string44 = "308f03aa9f8e2055a27007bb566fd24068cf518e7042aa000a0bc53b29214c9d" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string45 = "30ff629067623e3bb4a4056527fdc3e9d9c7b2428836445ea58a88c720173296" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string46 = "3101575fbdbee11b2d4d592f92582489c842f20fab0cb2ade9f2f3a207c202d8" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string47 = "330c1069831f7c60d89436905cb8ac6794d40896e9b8b5e539a2c9876a9cd324" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string48 = "34abcda5eb491ea4b167e4b2d9aa157adb87f035c1fbcc43aaedb6f9e3018418" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string49 = "36152e9a1e47217f9aa049b7893acd4cf08098874396ff06b0c52373bedab5fb" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string50 = "380d521181512fb9f4276d6f8fabbdcce082cee36efe133f68000a153ac3960f" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string51 = "395fe3d081d4bcd031770591913016fd6f5af3e7fdbf29219610acca1da3b6c9" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string52 = "39f119574d66d00a12ab7ed202bca6e41204bf838fb5f58ca170bdf76beaa445" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string53 = "3be15a6f8a0de053d4fde83cfba6880cfbbf83566b37c35a6a7ab82a7dfc3441" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string54 = "3c5d123aea23f54ce965bd72d3019945db3f07524fba2e76e36a6a0efc0d8650" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string55 = "3f11e922d2e804a34396aab6ec9e7e48a23be82982a90f7b1d407c9b92062991" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string56 = "40dd6156b4167e4846f1ea091960a88547de9d3986d96a7b9044a934aec61d86" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string57 = "4363de01f1dfd6b393f889bb916128df95a02bc1df2c294e28a48bd197a685f2" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string58 = "43ba05d30fa8d86631e5b24dd8eb9a81e189d146a3eb39d6cf230329bce81c8d" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string59 = "450bf298cc66b2d739e6270a9e509eed80026db3551e3754b3810b63db62354e" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string60 = "4549122ba17882aaa89999d170ca7cfe4d2f4d9cc9b6c57961abf276576c9d42" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string61 = "4585828aa5ae1aec2a5d5bfb371236dc180ed47489a6684d468b8b83a5d300dd" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string62 = "4600b361c95e232cf152cb7a0e9c004fd8e76e577ced2bae2e063dda12a5c50b" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string63 = "47d38c5f263c1372cb9ce16e921c06cf34911ba15639f6151e07fb47abb296fd" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string64 = "48174210fbafbc975cb8774bc4fa277aceb5a1ba565deef2df244173a21ecc0a" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string65 = "49e7c86340e6930402911320150a14e5aad183efafb8b56747d97a8a5469a187" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string66 = "4c8a17db253b2eb5af4596e93f8f766f815546c3b40700e8d88baac680a579a9" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string67 = "4d66ce63e4917a7e2749a851733faca18a04ab2a289aa5650ca99a7f806a3c7f" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string68 = "4d7fa7fbfca88ec9adb9e227f4049a544acd312dd5c3a4d4f936e053497b7d65" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string69 = "4ee1ee85ab16e36d6dbc5b4d8795375bb10edab50e451eed5adf69ddd4792575" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string70 = "52820d7c8b0fad129a6d4d4e631d627dbf63263c0c720569afbc43da085198cb" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string71 = "546505f3c8cb7cbe041b77cafa77a673bd38285e3de9918825f2f7f4fa773299" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string72 = "5472468e92c54af495a753b9feb24fa90aa0e0d321bebb9c688fe5c9210a1ae7" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string73 = "54d32b6689f4ae55b5402f89cca28cdd4889798022d1aee11674a4e506cfc7e5" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string74 = "557366669af1df330ca6a7f7488ff60b77ac3f99cfc8568a9759ce24d55563e5" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string75 = "564a0f3db972920e005a53d22f8062e10652bcb9fa9e2ec4218fa16446c2c344" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string76 = "56affb1b7a635c42aa5009f45a7f2e7a1bf7fcbe6c19a4c66a89872c2f2a991f" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string77 = "58553520765d913785914cb41570a76668b07e43c40d313841f7c03fddc899cd" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string78 = "5952611ae5f32afa4649c7414dab74436554ca71518ec8bf941041673818a639" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string79 = "5babcba4005adce8f620995f2a56e5d6bdcf6695f52a539bdaeaff889d47e8b5" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string80 = "5bd56a5da478c542e8265d5fd15fe8ba90f720bbb6a2649ea6c4ddd5acb77d85" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string81 = "5c089eabdf1c1446168d69c1efad0fae0d0217d8a671539bf859fe823248850d" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string82 = "5c89234b305a4a87b77598e6c4490a789cf9312575e3490f226a301bbe76d3e9" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string83 = "5d2fec2dafb0fd853fa2ff9d4b1314fe47470b59ce0b4d2f3e004d8f4b2bb339" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string84 = "5d80f05f43ad9ed6f6e2ed7ec55dbac0a987e58eac50129772a27ac2ad5ebeff" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string85 = "5e0426cef7b6c07eb8844af83c77aed5deae6b05e380690f83acbcead46cfe99" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string86 = "5e08786b4e4cf505b679ee2e3e03922b9886d6876aa406b123b791cd94497ee0" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string87 = "5ef00c89ac391313af63b02f4f8a1fa5509c6a6bddf98c2299a765548cae5ff8" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string88 = "5fa64857a76906be355e08a22e0183096bc92e63747a216217356daec482bb7d" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string89 = "60cd72287033962ecbbe8c27c7cb84dd7aeabd183a338ca4195a5b5275138076" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string90 = "62d7b075905119d8ab637df0f4348aca30ede58adacfe6d05cd3951db128ba91" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string91 = "630206b6d7b631b431907ab292ab6576e73bee49a3da3456b9caaf2ab8c027d0" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string92 = "6419610ef4957f7d62fdd16b22764a68ff694a612449195b932d169f523ffe20" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string93 = "6486fce494f85803b4abd3c18cadd14aa65cda411ed3511a598a7628ef2fd1de" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string94 = "666e400ed79f20f4f846cfe6bbcf9fb90fbff447695d217731ed5f830afb2f3f" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string95 = "66eda7f0e6f85ede326a715db2d5796a163595fdcf8f8c5240b2cfe509ef738e" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string96 = "67402a451ff767c1045a79d5ee001f255f9b5898c67f76cd021c586e0998c0dd" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string97 = "681f20b796bc6b59048b2eecf7a05884cfb1ea2464a14364f0769a10077bfb5b" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string98 = "6844205e2b4a41577969581d5447a6d0661cf885daacf50092c777ff4f85328b" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string99 = "68715639afd1f47089068f9de486068471fce5fca4a07aef888f960b73b09d56" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string100 = "68b38ba64f0639f6c5b7c95e2d19676574cf9cfb2034748c46d89811546f3d88" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string101 = "68b38ba64f0639f6c5b7c95e2d19676574cf9cfb2034748c46d89811546f3d88" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string102 = "696fa827e966020026d3d380e63529eb5075a608332788bffd1ca2aadb94062e" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string103 = "6a986a22cb9ff63cf0f9c7ac240eada15806a6b1bc86c61242ccb73d8a24ac23" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string104 = "6eba09a7e386379e173bea81ca5de348bef4c0f024d2efa963ab8d3bb8b37a8e" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string105 = "6edca5b408b075285b85db4ebfe180dc86695c387f5005f58af8c53a7d36b1a8" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string106 = "6edcee9130bc97aac10f1d04e9a3c86b20c38a66c1aeed24c4e2244cddfd98ea" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string107 = "6ee659ad14046e38ef7a00c2afe4785674015a5ab08cdf78cf40fa2eb11a891e" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string108 = "7455b514720dacb5dadbf5c3cc1a69614ded8375ebe23daf0778441af6da907d" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string109 = "748db6b8df67896f3adf369e785365c439ec5500daaf480e932adbbfd28ac0da" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string110 = "7521ae02982e13b74da0f4b9781b66394ffe8755b5d8c2dc3c67eedbb8591729" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string111 = "7535ea41cfd717ec0beb5dbc2671b7c66e1fb34ef904313899946f297d943e6b" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string112 = "75e170822ea113698c86a194968b088f62e391d9f1151f3b3184decdd8d30d35" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string113 = "772d623dd57c74226010fd7b330a5e6cf7a6b59ae37fc4dc9a6b47fe46756d99" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string114 = "789b38bc3c55852ece5657fe808a7aec867a151f8a3f7fe648adcd15172e6278" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string115 = "790bfe46db189eba7c8d9464da34ec62511b9b2f3ef0889162a5682910563875" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string116 = "79c98d35d02ac92c72aadf48a1ca55e2b7afe5a41ad70e5cf0467c50a84dce22" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string117 = "7b23bad83e3921e1d9e528b69b7d643b646231e5b736f8588698326c527e31a7" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string118 = "7c772e7a840bfa0fa04609f6b8b2938acdb565493514d85146ccf589f04cf12a" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string119 = "7cbcaba89fb2dfe22cbeeaf2426379560f015d49f4dad0caf2cd732146d96b84" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string120 = "7eda8b7dbce7550e3d56092a4f4bdfe23df822c33e9b5cf20ff986946f8882b0" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string121 = "7f27f414ebe84f189adc68a963c7735d4cef34307a19cd0c21243ec202f9f456" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string122 = "7ff4e1c0fb6e485d203b3d484b44de78e00caf0c84be600e8ef94062005b7b9b" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string123 = "8067eadec99ed1f3d97a706a29bc7d2713c4d163973b383513cf41641e7c0c8c" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string124 = "8154e009a82ae62f597ac8b9da160feb7d74125987bfa3a65283ec19583a292f" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string125 = "85057ff4c0fc97cb3b9b269c2bdddc0611cdbd7d748c52a2e4d949de9cdfb157" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string126 = "8579d38432b7652643a84d0fd7edbc78668ca3f91ddc1d78ee8840a7a35fa9b7" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string127 = "8768fb4f5c0829e3ed696af614ff761ca72b5538bef2073464f57eadc76f5ed4" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string128 = "87a25f52f233c1176eeeab554a2941f1738a9e86669fb7febe8155d15ddf5530" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string129 = "884a510aa8274a74bd77d27e5ae3b55c55a55ccc115ef0985d10a69b359e1453" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string130 = "89af64dd653594b71277b175037995b356d139881c766706a4ab1862250a7f61" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string131 = "8a1d6e1d9a8494a491c1f2fef92f0243f4d39406fa159b4ecb45428148fcbeb4" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string132 = "8c1fa8087f1f0542b4b982791b6b403e278a3ff6154ed37a20f6c590054edda4" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string133 = "8d59755171b977af9ec836990ee55a4d1f17873d7773131267b774b14d121fff" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string134 = "8e3a219286ad2715712ada61697d622cf5eb597a05bab126546101cc48e0991b" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string135 = "8eef0831a9aa9bbf01ae154c47595b024470c07be4c80b37b73b47590467bc32" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string136 = "8f1198f114049ac2a556308e557acd1ab0174bf7943b2da160be8f32873f81ea" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string137 = "90803cb7a60a71766d20b494eb85e92789c3b0f6212f67595540ab706cb734d6" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string138 = "929081341e76319dc5209b58611cc5304b940bed099b2b63589534d1963afab7" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string139 = "92d2460414d1b79ae54466442eae7628bbb343c70948e8c2f9afa4d158a0f3ef" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string140 = "956c78246b4873877ac8e1a0ee7eed3ff7f9068826696f40f8a0577c55c8f184" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string141 = "96c82ea18a4d63d57c4ae10b16e9761fd7a29f92e0704850783768f561e9b85a" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string142 = "96d4cb5937b2b5a38dbe2721ea427ca64ffcd745ecaace820fb4daa1c322f696" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string143 = "96e1cc96595bc8486dfef57f78f680c49e7b19d12649d43fc6501d7a599b4657" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string144 = "96f6e9c220b74cce941797d7019d76343c94e257c21b3e92869c0d124d49eab8" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string145 = "9722e8ce213b1c7571ef7c1df9f5777be11289e3bcf9911e0af45a622b5d50c1" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string146 = "98b39f9470d2ed0cbf458c04e94dc5762c8b72cf4fb51ba2bf641fdc4462668e" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string147 = "9a22c27e8df3ce1c62a160488a7cddba8c14696c0e0eb406c0c85eab8c243a06" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string148 = "9a52905fb9c6ed8f3c34111f905d0da5f54dbe6868f10023d5551dd2897e22c4" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string149 = "9cd1f8564ff1c66d969b01e117e922063213eeaaae20fd5c725cdbf7041e4831" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string150 = "9eca862c8cb8490e6b853171d95c9db07d3f306b3018b0ee5e567d3346d8b2d5" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string151 = "a10f6df2968d892ca277eeddb104dce0bda26aaf47b6a29fa37f6ef7b9b4b330" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string152 = "a37e18adcfa7a9faa14430814c622ad6a321cfa65d53d8ca54fed7a55f7c2806" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string153 = "a49b64c34c17e2f94a789517960f3438cab8b92f8e21560320be9ef68065c9fa" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string154 = "a51ca6422305b85196bb505e9f7e3ba390af7cd442254b10753dc2c101ff5165" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string155 = "a578c81ce8548ef3f5f92a572c15aba6369fe262f19e0bfd74b694b3609380f9" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string156 = "a5c16b96d4df537cdc307206b955f7808b58fc2fb425a327bcd6e0bccf95c1ba" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string157 = "a7a2808a64b5ee630b2ce13597623de03ca5d7a27870aa72f3e0f8156f20d10c" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string158 = "a91962e86f2b0b0a3a75a097ad056c5595dce4a66a204d15507d03da6eec699c" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string159 = "a94fff0ac12fea9c27ea48726b7cfa94067884e0c0dff6b1f7abb2ecccee0220" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string160 = "a95fbce75c24a2262a98fe462872b23207c9c445ac08ea729236d29231ae3562" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string161 = "a9cc4cc132566b4d7ccf7def13d41d8968697033ca728d29f3eaa09074ade08b" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string162 = "ab6763f2c25e691d68d58da97e7dbedc989cff797e69896e20308bbf65531f90" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string163 = "ab83898f2137946267913dba2f4f3e0cb43bb418831b58e6e8ecf1d3a8dcc58d" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string164 = "add4bb5104c6fdbb035dd4440efffc28c5b01fa7d333eb42c541f485dee87695" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string165 = "ae47b091425623f74f010f4ab937cc14b08dc1c815f07626baa20fc03d424a11" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string166 = "af8851ad2bacdea811ccb1525e7cc6bc73e082034b7c04f6ac5708708ab9f493" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string167 = "apt install gost" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string168 = "b19a810320e3d27743080c6732d3ee8caae0c8b747df6001b81b0a1fb226665b" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string169 = "b19a810320e3d27743080c6732d3ee8caae0c8b747df6001b81b0a1fb226665b" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string170 = "b246e5bb88a8e76fe372909c4c3fdaa09d69929ec4d0fd8e373936270a7baa0c" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string171 = "b4c80f3e5fcdf37a0d165af88b219bb2e3ce6b435164e6048b5f1b618b908fea" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string172 = "b6dd2b211d156dc7295cb5ff0e65eca60ba2d1a86b321ad9bcc4fd37f7ab423f" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string173 = "b6f5c4dc870fdc69d0309c5d5a2a5d48a924a5c14a62b8a13228f071749739b5" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string174 = "b74f47cf6fd216692dc71832ec8910ddd60b64b08b0aa6593ee83e7c08416f73" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string175 = "b7e45744a48f5a5db2177b70a0c6741909343d2393045204ebf6c740c50e1de1" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string176 = "b80fcbbc7283e4737d325cd9566c3269ee97cde42c1377721abab7c45d9e518e" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string177 = "b92dd2f3e8834af0a175dcf8ec3463b7b1012a8f23769fcbe96e4062505bf3b8" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string178 = "bb5f93973ab84243afce3f94f61b49887f275bc88db4e1fd892ab11a9eff7584" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string179 = "bbab0b5d719860c14954099bbe5f641c3594ffb1ad8d7c91c7895c5bea221964" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string180 = "be547f029cf462e5654c5d30c3833bdf54cfab966e6287a2f03dfb6c4a16da33" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string181 = "c11dc344bc262b1034a8cc98fe5f1032b4bc4a6cea372399884746e7fd278944" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string182 = "c32e4b8d04c97c4ea36989159350bb6b90ec7b7f6328da448be3c94c81e57bfd" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string183 = "c3d703c8e406f542bb9688a3e31c8164c8a34ff99785e256b2f7da8ae73a85cf" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string184 = "c3f953d4dd3ae26e5206c1194b1baf5e2d8b8a06778866eb62dbd493db500dc6" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string185 = "c4cf6a2d28fb9c4fce9337cb06adc5fa69601eec6b2e8d10bc9cd3a211f06e85" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string186 = "c6599963f89162253d6501a99425525a3406309a757f3515d957d5ff2452dffd" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string187 = "c685a8322f7e7b2d25860ccdf8432d20f2077fd2f7480fff39f9b7bd4a1da5ba" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string188 = "c764892be19cdf290c49fc9d421dc1f4f8359a1c1d127c12c3a3f56f7fe199c2" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string189 = "c7f1a98884e039f619255fc3f5ae2bdd90f6bbe46f00f7a60d72a40e82e4858c" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string190 = "ca9c8dba1b481536626a833232ca6146eb1128f8a4f4c6cb480bb37e771898ea" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string191 = "cd84694d8b390661c5295f76a523381daaf840c0b3ef16cf02b11086ad8d4028" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string192 = "cde2bf2225a77d8e5ffded509dbcd87d7445101a67acaf5a533e5884e6240beb" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string193 = "ce360e6f1b4a634b603f8ac114e938c057bb1cda5141a053d83e16bcfe08e373" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string194 = "ce3d52dbf87883133296d17bf791fa8a248d7613015bfcae22ae29e0fd0c6ed3" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string195 = "ce523561aafdc54a24581460262853a579dfeda9653fb88bec95e3752a370118" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string196 = "d08e1e80fa721e95a7e71a7fed9e2ce0b726207f1e3ee96d809a6f0b34de4c05" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string197 = "d12a87b47c9213d80b8dfe9626702c953ebbfa92320b01f5f8b42a520a232537" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string198 = "d38000d3b741f587f2ddaadafcec1b1764a44989115d2c674895366692b0d545" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string199 = "d4ad1e550ef4d054f3c44601772f9df630323da7b8d28303c649d36659c63e76" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string200 = "d5257c716525f4cc42778285074e6425b22a272333d08cc75fa27334025b4c90" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string201 = "d6debc94457abfce0e9fb02187fab3555dcef123591e4b167743d6322f02594a" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string202 = "d83b468e63c93a1496d8205ae9ac103540e23f1bb9410fca97020ab661552e11" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string203 = "d84969f4cdb8cb0518ecff3a0e9b8de406586afbd3ed9d7307691b375d2eb70b" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string204 = "d86c3884cb7ea73c0fd5e67c49e5375cd30fa5209a46f1bb620c1a8f52964488" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string205 = "d8cade3974728b8a3221c96a2b4c6beca41f13a2092cfd65deea83be6c78c6a0" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string206 = "d9bc47b827286a20cdd880d7d1abb2ac7b0bf164bfeab44fcfbbd1fb29f815bf" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string207 = "dccda6bc37067f48e8efcfdeb8bb67b3a4475ef693bc10228bcba271a24ce5de" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string208 = "dd1de5874d1287a59c05bcc7c8c298c9efaaf7b3471bc6baf9f3ed645951313d" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string209 = "dd3e4227210af530698b5669fda6ca0e604cf23aeeb5693f9f700aa9bce6256d" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string210 = "de00ce580104a4afe01a1294a554d922103cf5a048708d022b3c231c5d841779" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string211 = "e00d839edac7e43f8756ac53d803ea51ca8fdf7b58a888f021d2964ecc3c4351" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string212 = "e0955f1c4b9c89c926928109a080924c6400136bc2bce8d673ebf42c1d54d510" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string213 = "e0d8fbe3a59bbf36170e5307ef979b4035784e35c0675ecc9309d35b7000a78e" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string214 = "e2d664ab3604b082e17dbd728c89bfdb82b5616f92defbe0cec24d94674c5818" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string215 = "e34406bea3c780144b827a7308a0468c53f773e4da11fb02ebfc91f76ecc754c" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string216 = "e40c9f18d7f47c131876d6ef9a29385802e0d006e75ead9906a980c751fbee16" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string217 = "e5350eb7c85f40bd5eeb5df8b3cd58805d39b2469a1c1c9817957fbab77e9427" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string218 = "e59ee7929f1c67c3aae6aa1f31299e0403430e7f25aecbcc572e19db79451d96" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string219 = "e671c90f050cc03b06a1c976db31a1f2f1a498730c63bb2a29d92c9e47af5f66" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string220 = "e7e999c455e3e34a8ae2238395af8d0b50dda79499bca470547ffba7ff0c4b39" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string221 = "e7ff1472a7294417e4f1dcd1c882de9f81f214b3f68f34ef4b8adca5af593c6c" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string222 = "e8b4edf6ac96c960c5462302cbd33c5d4673f2c1f88b6166b79e4766508c658b" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string223 = "e8e3e2c16aee37f48167a81cf38e071e7d0fcfceb2a060c3357f9cbb55fe78b6" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string224 = "e9ff51cca46583fe8f3ec4077fd863edb916e4d170d491100e4e35d8fa782a14" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string225 = "ea92bdc7ebb7f0337690db66b44020aca6e1fccc36398b165847848a9f91c6c8" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string226 = "eb74e547aada07218492e1fd08cc0048ff2ab30cc4d5a947122ca6385435f54a" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string227 = "eb8e44c7b95215c53b1bc78a95fa58fc7e8a47eb5d7c2538a5ac7a285857d79b" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string228 = "ecf0123e2c1131eab2d4deb4ce43f9ffd7be2bf379fef19ed7730ee2ebb586be" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string229 = "ed19d0c0a65e0eaf321f86f95c1026fbae834876a8431d65609937e56e240ef8" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string230 = "eed97f810223bcf85f69b84040fd3e44e4a4569b4fab06da412c93fed71aef02" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string231 = "ef1d847561dc29afa96b2e827e7c9a94facb9b6aae2b09ddb33c3c50ab581ae2" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string232 = "ef37c5075ad3ac56cc95adace9e3686da6448cfcbe8430e997affb263e1cbdd9" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string233 = "f0d19d73955298f2766e55ff49347e31b2482a3bcba107ccbe38630b1aac355a" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string234 = "f175e055b67f3cbaf4588a9decdb4ed6bf441ea28da502451ddd3da8ca87d390" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string235 = "f2f4b7576e0e51425fa90f94f272d0163571f90a0ecb8549f8b97dbf89c5255f" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string236 = "f53753cf2f3d9f2200ae3b959299cbe1153851c534ce19f54daf281fc9238f69" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string237 = "f669e3b5a2053c74212d0c6f932651dd02fb5c4f5483061999855180b8257fa8" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string238 = "f6d9c3345d2a1b88d31fd25eeedcf6947ac3e1ca5a693439894ef3c2bb2669f2" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string239 = "f7f52607771ce2dddde694ebeced6e2dc438a29c8b87cfb93f125db4e968107c" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string240 = "f891dc701c6d272cbc51bc2975a80e42f80d814f23cda2e9d9c1c005ec216529" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string241 = "fb540480308fe9d575f799632c7a655ac05f19d6cdb58f5e6ff62a11c7f2ef84" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string242 = "fc258ceabaf70cc28b8519a46a8045cac406d275707942f88e952621c6c382ec" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string243 = "fc5f6cc320156278ec6b2f26d97fb4d56a429cb4365b893ce0c9c602ade37b9a" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string244 = "fc6b300edf4c44463e17b8ea10303ee642e4114235fdb0096384f8f3b5f44ce6" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string245 = "fc97d73cd3ae1d0e0cc492a7b67ef928a59296fd2bebb99e753672b964813895" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string246 = "fce455e607e33bce8fc0f29bb1bbf34e7a886c39bb48995ee3af25a91f2a57f9" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string247 = "fdeb3ef3bb907499be9d8fda107426d15ea9535e0f7818a206ded082f31fcbbf" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string248 = "fe7fb6e885955c83dfa6c9797f277b30971ec4f0261cec7ebbb864408fa02aaa" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string249 = "ff00ffad183c58baa5252cbdd086257a9ae7b4539a02950eeb3347049e606c5a" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string250 = "ff4dc01b1bd4ab8682316280bd90cbc15f8cf14eca91e6a5180129b1fd39f2df" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string251 = "ff5892909fbe28600444bce96bb710aa2d1eaeb69231997ebfa76d40d87fe3ea" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string252 = "ff63fca9ccb4a827d0b62fc9bdcce683ef8ede7b11f2a0054393e0d061d8d241" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string253 = "gogost/gost" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string254 = "go-gost/gost" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string255 = /gost\s\-L\=.{0,100}\@/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string256 = "gost -L=socks5://" nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string257 = /https\:\/\/gost\.run\/tutorials\// nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string258 = /https\:\/\/gost\.run\/tutorials\/api\/config/ nocase ascii wide
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
