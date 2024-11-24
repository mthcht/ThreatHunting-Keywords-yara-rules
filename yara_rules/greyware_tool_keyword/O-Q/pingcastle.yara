rule pingcastle
{
    meta:
        description = "Detection patterns for the tool 'pingcastle' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pingcastle"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string1 = " --doNotTestSMBv1" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string2 = " --scanner aclcheck" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string3 = " --scanner laps_bitlocker" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string4 = " --scanner nullsession-trust" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string5 = " --scanner smb3querynetwork" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string6 = " --scanner zerologon" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://github.com/sense-of-security/ADRecon
        $string7 = "/ADRecon" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string8 = /\/pingcastle\.git/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string9 = /\/PingCastle\.zip/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string10 = "/pingcastle/releases/download/" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string11 = /\\PingCastle\.zip/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string12 = /\\PingCastleAutoUpdater\./ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string13 = ">Ping Castle<" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string14 = "00f66ad0898ce930b1f58792baafbb71e19645ad86ef0f0827805d8fe366de91" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string15 = "01d64306425b2e5c7a8c53c9e696719a8704dc2b011248f52fd981d7a437c1e8" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string16 = "01d64306425b2e5c7a8c53c9e696719a8704dc2b011248f52fd981d7a437c1e8" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string17 = "02d65d123f0bf661831666e4a9b10b1bb854b7120455488b0e28a29541b7ad8a" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string18 = "0747e08b55fa97ea6d21026781e1f5d2eab2a0fedd42073fd17da0e451bfe1eb" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string19 = "08140ddc8cd28056e9ff871e25afa4c2651115ec7829f32a7c398a1bf97c0b52" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string20 = "0b200be5c6584356e7edc5d18f1ea00f7e467295b50fd5437bf119c99792bfc7" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string21 = "0E5D043A-CAA1-40C7-A616-773F347FA43F" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string22 = "15da50bc2201c1b3a8a7ffd4dbbdac655f2419a8ed47e1aad32ee4308c32d76e" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string23 = "235175349388872210b0d1d5e178bd94a850f5180d63e5c7ccd59101616da5d5" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string24 = "2534aa9e6f59df7e78600419268278175681c673a6471e0f4c0b046302b30146" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string25 = "2534aa9e6f59df7e78600419268278175681c673a6471e0f4c0b046302b30146" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string26 = "25b3e1f0526fc55142fc27fb7c6c8cc37020edd621768c086938d24dbee2f97f" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string27 = "25b3e1f0526fc55142fc27fb7c6c8cc37020edd621768c086938d24dbee2f97f" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string28 = "314cb197b38516ee6dea9f5494587a21f303ca00e4894df11e4739e3bebfdc6a" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string29 = "36266479e235929cc0640fdf68ca395aaf851273908bb06c3b4143d8fbac2830" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string30 = "38a99341371c90b6029eadb9c2a5508b3db4263a1b869948d43edb9cf04bacf5" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string31 = "3d114e763a2bbe22290cdadd30241c690243d4990539c891273a82ef50460940" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string32 = "3dd29906bd9c9a5db310bf6ef3d8142dbd8c5c69d6b61a91805d0fce9bf2bbda" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string33 = "40921f28b6e294a3511e27b2ef2026561df96ac0908f16fa90b8af5849e981f4" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string34 = "44f46a9703c0876bf31acb1ff75b29db81ce484e8dba90ff2b13e2448ebba9e0" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string35 = "464d8deeac82443951b7c6e10caf82f4ba0d8ee6687540cc1047404a743465b6" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string36 = "48e04bc2e7edc9c057767539cb7c4a8b71e8196242e2cb8e461536902884692c" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string37 = "4c4a26fc3bb0cebf08ecf55e88eb1a2bc25e11fedebc7407198e84439fe20075" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string38 = "4c4a26fc3bb0cebf08ecf55e88eb1a2bc25e11fedebc7407198e84439fe20075" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string39 = "4c4a26fc3bb0cebf08ecf55e88eb1a2bc25e11fedebc7407198e84439fe20075" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string40 = "52BBA3C2-A74E-4096-B65F-B88C38F92120" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string41 = "52c57ccd01efae71adb244f5867b879e14b486478681b04a1bc89d92417697d7" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string42 = "532f68e5acaadb28368f0e7f034e132a82e5b8e0aa1288cce4d71f8c4ef3bbba" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string43 = "58905c69879fe708108827034d276893c207432decd282a1495e8752a392fa58" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string44 = "5b26b766b18f4373017a3c7fb5f771673d00e793eedfad822d4cefb7e736fe59" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string45 = "5db5f0645d51e2e7c8a2a3ee4c66b65f3c4e483716e8106220ff2c3358415596" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string46 = "6675d7eb9dde349a58343e5a155e9f530eca6b6afd47280f331eeb0523421118" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string47 = "6cc029abfa617d77e65ca70717fba6cfb418110e3922728c251aa8150b81e64e" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string48 = "6ee1775d22b9392a4cf9f14450eb072ce78799bc81cb82e3c09c8bb68542cfab" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string49 = "70d2b7f5e3ca6061206e54786b04143fc5154eab4feaf854797aee3f523d5175" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string50 = "7218d911d8644674912e3871b6dae46af2272b63f2979d121db86f8e03ca395c" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string51 = "743e73b664ae59c68042364849629ca96fe81d3cba0e48e4e7f4f30e71d04f32" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string52 = "74a4277e37419fd55a972cbaf18d6cb1334c544346c698f3eb59c23cd2e3e82a" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string53 = "7585ced4ace610e2b5ca199838a277d6eed393bf4ad7bbf687ded696e67399f8" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string54 = "7585ced4ace610e2b5ca199838a277d6eed393bf4ad7bbf687ded696e67399f8" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string55 = "7749b3c203617b95dce12ca8a044e5206e585a2f010c011ee87d7251fb1d0a4b" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string56 = "7a7a44335289a4612f0dd903745b49853c0f8f53dcca01306d5d45ca1611a2df" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string57 = "7cb8360009c9ee1fab996e446a5d1f2d1540dadb9256c9787f3f30e33aa5e121" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string58 = "7e09a8fc84665d590659493aa9a832945c6ff9b25bfa87f3bd2aa9636781e87a" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string59 = "7e09a8fc84665d590659493aa9a832945c6ff9b25bfa87f3bd2aa9636781e87a" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string60 = "7e87ed799b7b8ca543691b5f261212cb3efebca5ed03e65ceea4e7dbb405ed34" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string61 = "806530346d15b80d28b3050b3a6d435025ffef592fa44b9abae471be6f9c0cb8" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string62 = "811db2a2f5deab16fc831dc8ff74172c121e9676a325bd8761fde7a863bcc598" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string63 = "83cafd75fbd94992f38162260fb8cd5f6388c10f4e0b40890554568c43a9fc19" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string64 = "88e0abfe14884bc8850346e1250c8fd54ee3f2de770f32d3ffecbe06c7769141" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string65 = "89e35428319e2e7ec6520f8f828c77e7a94dddf7137b17e0585cd98f5b42be4c" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string66 = "8b6078e8fea18dfd13473f20cd0d7e74f2724d66183d5f44437139d996ec4794" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string67 = "906b60debb9c88e649118409185663b29d3f29f668ca58de314890743a2c7277" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string68 = "90e1610b1a020875e5d02774f28770a32787cd4379ce184890979e8f241b904d" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string69 = "90e1610b1a020875e5d02774f28770a32787cd4379ce184890979e8f241b904d" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string70 = "90e1610b1a020875e5d02774f28770a32787cd4379ce184890979e8f241b904d" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string71 = "95699dfcbe694396000eeeeb2df293590741f0b912ce5f31c5844b0011407d44" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string72 = "9bc4890f95874f3f6931e15694b0e7f37f2a7a18daf460ea109fb5f0c8886800" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string73 = "9c5f80d8b37be0d48a0c13a3838db1455aed0c3e23500ac7d9293bb779544e59" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string74 = "a18c0916da1f5900730a30f152c36bd706cbd1e2f9f8bb042207de5ac3ef8097" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string75 = "a5209d425fa5e65dc69e5187454446b5a035b3762a325b6ba0606fc168041c76" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string76 = "a8d276db0a9f5d22cd2757538f19b4fc1e234db045d7355aa656326ae8acece3" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string77 = "AAASCCVcEQQCADCgAAARAA4AGwABABkAAAABAAFbFgMIAEtcRlwEAAQAEgDm" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string78 = "AAASCCVcEQQCADCgAAARAA4AGwABABkAAAABAAFbGgMQAAAABgAIQDZbEgDm" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string79 = /ACLScanner\.exe/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string80 = "ae4825d459669ab8cba5f72cd12b587f7a61d5da96e6e54db1bd8c238bcd83ae" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string81 = "ae4825d459669ab8cba5f72cd12b587f7a61d5da96e6e54db1bd8c238bcd83ae" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string82 = "aee777ead4791c2d6a5420b0625e7fdea13f6d84dedcaff924a5845df5f4db94" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string83 = "b62fddbe045b405c39c6d9252805804619c0551d527b78806f0f71246b87b812" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string84 = "bcbede4c733ae4b0abe3657ec35f1917dcbdb680aea8e05431d6fef074b720c2" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string85 = "bcbede4c733ae4b0abe3657ec35f1917dcbdb680aea8e05431d6fef074b720c2" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string86 = /bluekeepscanner\.exe/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string87 = "c5719fe52a801b38f7e30386450f5985a7f378147e00d1392b12b902730f6601" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string88 = "c59f22eb5c115a9c633a0b1ff514787c1ceeca2bf4a660f0232616b3fc8336a7" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string89 = "cb5618be68d7de48075061262b531c7dd528274a7537195f33dabdffd48a058d" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string90 = "cc45f912feb2ff63f5868a2474716c30c75b0a7bc5be629a26d3b03acbf289f6" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string91 = "cc45f912feb2ff63f5868a2474716c30c75b0a7bc5be629a26d3b03acbf289f6" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string92 = "cce6497c3f06700ee80fbd145bc228aa2016f1d3973e1a22b5d6c1bfbe53a447" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string93 = "d21a159ec788b457b98da90633ff963124fe551ff66b86e48635d35175902fa0" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string94 = "d21a159ec788b457b98da90633ff963124fe551ff66b86e48635d35175902fa0" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string95 = "d3b9e8104fcf67fd9ac71d9cf0bc29d3c870ea60c79ce8b9e9d9bfc1d64c3809" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string96 = "db71a0c966e917def48ab32e67962d37dbfb4ad527f3e3c9615d6a45a69ba69b" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string97 = "dd550c264f7af33bca01b0e32d4504e8e69b0b7ab99b472d8b59b818c83b7b96" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string98 = "dd625dc8684d4a9a60e5aea80ec9379841cc80f2c60e40d9737c89de5b32fb04" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string99 = "e079f9dbcc51b905759c6a17d46979181b432b6e195aafaf3a3453b7d1d687dc" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string100 = "e854c1bb27c02fbf6f86bbd1ca750d9cf70cd3a978d142e6d97119bc81cb1ee7" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string101 = "e8e73f8cb4babe6bf59cdfa6090a183d1f8be8da8e13b19d5b8d66126800b41f" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string102 = "e96e655341857f858ba7deb75afcc9eea4b8cd24af772720653ec7ce0617eeef" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string103 = "ef13e3756e1108a1dc018ff356f1b50c418f2ddd25b701aeaf52f959c883c53d" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string104 = "ef13e3756e1108a1dc018ff356f1b50c418f2ddd25b701aeaf52f959c883c53d" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string105 = "efa152281662334f2a353cd4819a9eba3b9fae144e50758487df31ab1974876f" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string106 = "efb4c1b4ea3b74fcab1947c248122f03cf95df33b17b8d635d3a50c3a91726d1" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string107 = "f681c61359c401aaad1cfd8b0e884a91f59499cb1347a42d9f4d4285e722dc29" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string108 = "f813c9c83c7dabb18c93222073f548d1b7bb39d5ed580011cebc9fb34ea3060c" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string109 = "f9c6e9fef6d2fd03cb701bd047dcb58c0949f13af975b081346cb14afad8c2aa" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string110 = "netwrix/pingcastle" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://github.com/vletoux/pingcastle
        $string111 = /NullSessionScanner\./ nocase ascii wide
        // Description: active directory weakness scan
        // Reference: https://www.pingcastle.com/
        $string112 = "pingcastle" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string113 = /PingCastle\.Contact\@netwrix\.com/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string114 = /PingCastle\.cs/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string115 = /PingCastle\.exe/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string116 = /PingCastle\.Scanners/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string117 = /pingcastlecloud\.exe/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string118 = /PingCastleReporting\.exe/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string119 = /RemoteScanner\.exe/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string120 = "ROCAVulnerabilityTester" nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string121 = /SmbScanner\.exe/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string122 = /UserAgent.{0,1000}PingCastleAutoUpdater/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string123 = /ZeroLogonScanner\./ nocase ascii wide

    condition:
        any of them
}
