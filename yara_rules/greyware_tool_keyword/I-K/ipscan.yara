rule ipscan
{
    meta:
        description = "Detection patterns for the tool 'ipscan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ipscan"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string1 = /\s\-jar\sipscan\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string2 = /\/AppFiles\/ipscan\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string3 = /\/ipscan\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string4 = /\/ipscan\.git/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string5 = /\/ipscan_.{0,1000}_amd64\.deb/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string6 = /\/ipscan2\-binary\/.{0,1000}\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string7 = /\/ipscan\-any\-.{0,1000}\.jar/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string8 = /\\Angry\sIP\sScanner\.app/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string9 = /\\ipscan\-.{0,1000}\-setup\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string10 = /\\ipscan\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string11 = /\\ipscan221\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string12 = /\\ipscan\-crash\.txt/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string13 = "00d223d61d1569d44bfe81805359f94c15c9549473762016605287c31733bae6" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string14 = "00e3b8a6e650a206a6070be87c2c1d5387c21f9f6b80d18ee683c2c0f5fd2fe5" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string15 = "02737dd93d82d2cc1e46914a3650dde655c34e68b6f2038039bff29bb2ec382a" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string16 = "02d7942d0d329dd9b3df2425926bbc8cb634e416b4482fdee73e5aa4e60e00da" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string17 = "02e2cdb9266754c45c205c199b3478e372c234d6a048a2719796bdb8d3ac2731" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string18 = "04844b7aee9a823f89337a62f63b36eef9f250d8b0b6ba151117de798e3d7454" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string19 = "0512029520eaea2237833ed86b40aadb61ab98861da8c135dfc513524f74a4bc" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string20 = "0522e7c0979e1598e40817e5d7a4bc05fd7448115237bd883c91f954ce3817a2" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string21 = "057519a7348a5e04eef59aafbeddcffe8f2027e76e141160a147292e24017d88" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string22 = "060978f4ecf406020b835643e9995ce4e33be8bcdbfc17e82781c8858fb3f971" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string23 = "0676d3458ff6562c5b7fb3229fa9b9fa02e055ea773ce8ecbe45c4f01c43febb" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string24 = "06c6c311f542cc48cf6f40e6f7d7a8769d933841aa1a5a532fca7015d14017b3" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string25 = "07c379cc290a52b11493d1edf234b842d2640963ba258b21b8cd16ad082d568e" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string26 = "087a45762e1d7760cb0a52f74e797ece192cf338a1c090c198733bd5a6166bcc" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string27 = "09c5de00c5304e6f2b2e3f031202fa6175748a451cb4e7d8c7c122ad2736f215" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string28 = "09c97fef43a054ad611912d81971b8e58395bfda3d280ef8242c74fcec0c63ea" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string29 = "0a15c94da1d3260464b1fb81195631f9c336471090aba0989424c75a02d4d91a" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string30 = "0a4958c4b72f0ec7aac3a9601675737d1ae3bdf80063e2997a99d5b3ffd45295" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string31 = "0b65b97063a6a2342da20ec4779b189bad3753dc596f7e79e72021fa17e20bab" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string32 = "0b7ff7dec2fdc2d87ef6837cbc2fdde8753da066959c78a99d1c508d1037b926" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string33 = "0c1ce0a85821e71d41b86deb8b16f43fe5150c376b3eb8de93979ead13bd57f6" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string34 = "0cd720bb196cf0e2025f393effe11cb888cf4a069add5b0ffa7cbf73635d1de3" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string35 = "0f49299cf3e23fa2b1c5f0f1869a8982cdde2613742508d81a901a4e52ef37fa" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string36 = "0fd4612b5f3adcd0d1a9afbcda38955ed3ce0e4eff1a7afdec9953700926c29e" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string37 = "102c6bc06ee275f6d3fb46d3d48e71b92abf2b7451e682749cbcae61e4791e05" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string38 = "10562b3a636cb93258959e76fa52708108f65e58287e909f4c041839df5863bd" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string39 = "1222d5ac68ab90dfcb14e3c2e2258d695de12b27d3aadbbd94aa85a3a85d4701" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string40 = "15c549c4a529d14185633144bd53bffa7d79d84916756cefa267071bf6871cfe" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string41 = "16689e0739ff392f0240dea50b9f48b720bfac3a26a42adf52729321ee5d1f9c" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string42 = "16cee34ed7af7175f622197c764fd0c69399bc6dc8b7d891ac76266d077c5415" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string43 = "16da15648dd1bc0da44d0d6afd435c1a664cfaf9b7bc4ef7eecdd796727e40df" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string44 = "18d131bb7a04a65222cfb35ce549326e9debb5379d04e68d3d75e2d4ae24eb7d" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string45 = "19e5eb368d5b82d650a5ab168f4041dc2f2e526569349319c8d0adcde091a7d5" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string46 = "1a1d59b366b35108f0681a69a77a8d67cae6d6111c589703526964e0243cf62f" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string47 = "1aa48436b6193acff1c9fe26e1456f35d5891aa90be2f203f5d59b77fa82df5a" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string48 = "1aea638f681b471f2bbe8714673b0c2fdd7f590b33cda162020e601f961dd4d0" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string49 = "1b89a1c5e9ef0bf0c91232fad88f31a6a27936407bff9e312a61ce5aab2bdac4" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string50 = "1bff328616d4205bf3182c51e6267cee29b03e9cda22671cf0f2c153a4e39d0d" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string51 = "1c90f970cc49e643c0c108f63e6d3a7696b2f28da91a42fc0fb234562f48e3ce" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string52 = "1d83e3da93ce0ef31a742f8f3ed6b77fc29566f7e3b4f7b240f2adf7c40a2036" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string53 = "1e6f9b25d6e296f2f63dac75b8abd30cc6f0a85cd7bea0579d081fea67085082" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string54 = "1e8dc49b24079e1f1b78fe64f54e0c222be67d45bbd2a6e5f13e06ca10d75004" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string55 = "1e9b04a795d2cf5d7c71b576c13f35873413e1c8031019e951ba65e39655be58" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string56 = "1ec5de34fbde95ee1b1237a78d01bd39925007ca1d9e128fa470ec090c176de9" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string57 = "1f14b24c5bf0a3ddc9af6394eab7245bd6af7f4c20322cd4177ef24e5e86bed0" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string58 = "2043a9ceaa7f2eeb1bb77a9fb932bb484c848d167680ee34fccbf1684a7147ab" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string59 = "216ed12522652f3e745cb0e8313bc1fe245de0ab6b8cb5846d385858d59ba6b2" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string60 = "2183b543d0a5fa662cb4413e8ad030499e3852b8466142a7040cd7fe0f4ef2b8" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string61 = "21ea0b982bc934dbe8fd26234feee56d1093961de376f41dc82b59adf19c1505" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string62 = "2236ee082c1c00e9423365db339a811a36869fcc4d3438e8c89982ccfe4917f4" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string63 = "229e1c2dcb1fcccacd2816c7a0e1ad43733f7a09cf76df4ecd53ccdafee8bdda" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string64 = "22c57d4a0ba5f22b33573aaa1d08f562375a9e33c7d4705fadadbb06450fff00" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string65 = "2353b409ea98230f05e0d26815ad1517fd49b5996d009612fe691f9ace020400" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string66 = "2376c3f4134f56449a4ef506be95da5ced01ec152ad558840c47e87ec160235c" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string67 = "2496e4de6363347e5d36ee031c9d307d5f6e2533a20fb0d49d76cc4a2980e3b3" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string68 = "24a8be4d92df01761061085589d4b912140dc5140861a33bc7addc00042de754" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string69 = "24bde49e5cce1189783eb0ba3c93b48c8f7d994328dacaa4fa2b9a7e2d04ce8c" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string70 = "257ba9e0bb8890194c9e8fc0c606ca928ee75ac9ac0adfc4d53b4489038a5bb5" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string71 = "25e40f43e35ae0bcff2feea99ec311ab0f1dfa84bb311972dca123f1be073c2b" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string72 = "26052ec687ec20c6de1e140266b194cc316b4ad5eef808e432a5f18988af2819" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string73 = "2b2705d375cb293e59fbd641bcc42936e458666acbc6a43d81a281091574d469" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string74 = "2bd2ecd96c79e54de7c0e286107d0a8def7a3f52fc1fd114736fe51ce6a0bcca" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string75 = "2d911f801c317eefce3ae952ef5a8c3625c0ba03c9dfb286534511958910b29e" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string76 = "2e9ce2ed5ed7d036357e30c59478f345a7266f3531c2621785b91186ce241911" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string77 = "2eb477c2093771c42fd12d4c6c4bd7b94b9b6238909bdd5b3fb872408ce127a5" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string78 = "313f6252693b97c7b97fd97da6323ecf9ca3342819e954fb23f1b3988d9ec464" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string79 = "3166a71c855545de502838af5fdec240655d4946cbf81e32181bee033a1cb86a" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string80 = "31a9863499b273ade500620c3863eac9d905c677aecfe8e8c3d68fad63e1e343" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string81 = "32544295fb7ff44cb0052693474c713aa5b9fdd0574bed4a29f09fad6b1733eb" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string82 = "3283db621b621cbd7761709125c8097dc52ef0b9329bd25c9eb79a162b86eb12" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string83 = "32ef83acc082cff716fd44e6f96f80c8bc39f1a3de74e59a2afcf71592374325" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string84 = "3327d1a9abb9c15aea54434986986bf094fca303a3bd0cf82189d32a0dce44aa" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string85 = "34d8c2352fa1c264b7d9146069ebc780495b896bc767c10ba916e5a55cb9d1a6" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string86 = "356d44637750712f238bd27f49fc6dba7f5ce22c92c83e94be7b9d3f59e54853" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string87 = "362e60a32dc864d5660bb7a9caae50b068bdd81924469bb014af395ebeef9a9e" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string88 = "3adee5344212720044b12dac4fa3e11231bb07a9cd65e2bd6031804278a3ef35" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string89 = "3b047ae119ef323d9fa486d1be07bcf85163fc392ab02ec37fd5437578d06d4b" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string90 = "3b29215b47016a94daad3066fcfa2c11599d03ced78e4f40a71cb152aa9b1d5f" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string91 = "3b9a9cc912b0817c09577835d094c74a61911213e0533f606f20a602ea3c1703" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string92 = "3bd117db83f5fae64618cfdf7def01d1f91cb00245af1bfbccbcd671978d62bd" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string93 = "3c577e92b14614dc484b1062561dbab2550708789fa1e70f7136c44195dd7275" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string94 = "3e7874880edf4af1c31a79d1291358791c9fbec5ee633839712af9edde7dbada" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string95 = "400ed1628aabb30719dcca007c4d5a78e8cfcb794d35621c787a76e20fbb58c6" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string96 = "407225db88e109bedc93d568ec7b0a241fc362156587b8b710bc2cbe270c257c" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string97 = "40c2cf70de786de022195f0e3eb003c0f81c4dcb177fd1aad0c6cbb489eb900b" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string98 = "410e18b7e5221f4759bc9f7ed1c2daf1fa919b588db0f3430819854bd0c3d432" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string99 = "41b647ed1bfa946a10402ea65ff73f59309ac1a208e304f2ce68664ad247e3d7" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string100 = "43a9334196ef0bd1d9c1247b7fac5110f4fa1daabd565f7ff5b6e2e8ae5102cc" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string101 = "442fbc52ff95adad5ab1e0325fe7a74c5aef1816c6870d83df2fba658edb208d" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string102 = "4452bf743b91f801adca4d2faeb2333fc33f22a478251d6b910f204f0f06dd6c" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string103 = "451728655552b12d5f39dc742f9877f79ba194ec57b2807821d09b9e4094315a" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string104 = "461c507d612d0d88c91ef4dde79f266ecbaa3b5518df24597b8b40af6dc90ddb" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string105 = "47e3c8363e117bc8712d431f05e7041f313629dd27efb004a369bf24b07c6908" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string106 = "491c9767bdd4c5b94794d52caa0d2e4c50239b235adbc0e2b4b12a15639ec4c0" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string107 = "4b1a9bf186122958ed2d540c0c182057421d0caf9ede82514fe9905705bd49ee" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string108 = "4b25db2797b029ea009c3a5267c2e7e91ad6857cd2a8603df19cb8d94e5aaa5c" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string109 = "4b4cbc201cc169fe490db4a53cf034b28592ea33a14bf38c9a422c1ab4650159" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string110 = "4bb56ba1129679c1f8ad298151de05396a2962b970f98062dc85edcabb7070e1" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string111 = "4beb7f83d9996c45b7d2f0b504400ad6b87c93793c231d629c47733e8275323c" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string112 = "4bec505b55c8b2271556dee2b689b05586c54cf1ba32a581bb5ebaaa4f42f580" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string113 = "4d31231f9468824107afb6c11e99630e80c98fb347658677cf2c1111d00771c3" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string114 = "4d8811ff14a7bb842fc02825314f76f7484264ae753814af74fc2412f17b1a75" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string115 = "50455d300e96d1d186ff81c97bb45d4697bd057c6a4fa92b280ff8782121ef86" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string116 = "50f0408d2544a0660a23acfcb9f2ef1a5883adc11861bc9f810367e45aad054d" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string117 = "50f914c195773487957cbdf262fa8e866e17e715bee3418e9591b2f161a16269" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string118 = "50fd26b82963fe0813a7cc5a5d1b4c2adb75cac715c498176e8bfc5aba7e5307" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string119 = "512f4208d0376a5c5b555930b8c4a3fc3a5a12680655b3d3a167888e6ef202b0" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string120 = "5273cd88fcbbafe3921dbb88f330a09b4b00c6bbad7d4bc0bf897558a24bb5eb" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string121 = "5343c3e7100eac4771f00f0b66e26a821be87ae8e8694815d168ad4dd5cd4352" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string122 = "53eb02c62b6ce83e8656eb978259cd26923613d545eb2d63ebba017997b2d672" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string123 = "564d2db592127c85b801082955d3af40a9e0a485a2dc5c9d960e8d685621b943" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string124 = "56976a6b2d3b62ef3e46626df51eb20a4e849e346a5292bf923481f4efb5da4a" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string125 = "56a728c930af1ddb0583940149de58fa36b2d02cd318e6c437583f121dbcfb6a" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string126 = "56d615c6338475744a0259e928f7f20aa88f8bd4889d7a3db3e5a0e5a55a5fb8" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string127 = "56eae0c5b8a8607a8f25aecae5069fe0555333beef9333cd44a2e8846740529a" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string128 = "572a3066b441a61d177c6858322547d508fcbeca9111bcc5db3087d426d9b687" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string129 = "588883f038421d2b273d9c10da1b195a75ca107c274645cf620934d8ee037e9e" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string130 = "58d81810dda7c93466ab675fb3429d65f4b658ee9c1c1c7113276906abc31de2" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string131 = "58f05a0c076f117a861b408411b8c4f1d1e6e3a9f15fdc0501a99a423f80f6bc" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string132 = "5abf08594b53850df4821a89755c9578b357577b1f356b2346b0eda7f1e47ba4" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string133 = "5b9244ba79420f46fc1a1cf762c3497767bc93b863f0224ce7d5051f81a6120e" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string134 = "5bdbde8744cb35a016a5af05c34df1e709d8c731dfc4206e5725e2dead801e9b" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string135 = "5bf7ab659ccc836dc47a5c60a8bc653aaed5ff945334f4f1af0ed596c23523c6" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string136 = "5c706aa708b87098f372add5b7c1693e4255462da1cd0f08ce60918e030a6085" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string137 = "5c80fae298c7042c21a46ba76985ab79303001af8b26ea073712d5bff68c7215" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string138 = "5e3df2bbf690bb6e9c58ac2ca4a1ae825d5242159846e5b712c89afd839f6f0c" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string139 = "5e993a83d506ed23eb4296fb718b1c2ed0dedeb5d3d65cc7860d6176cf0a0ee9" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string140 = "5f2b814295bd21c4480661eac4a9c57b50030d7bf7a7fa4c6f9b0640feb5eb9c" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string141 = "5f36bb51a099a20c72d69123aa5b17558fa78ba37b5d340b8db9877e4055ad0e" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string142 = "5f6ea6654bdf44865cba30a5cb6286407d0362936dbc8a8ea2b6e7859881f99d" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string143 = "5fec32c0fd6dae3b84bd2533e69916a65066176439e8b8481dffc2c565ac70cd" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string144 = "60f5f94a3dd286eb0339e370e3a1e09af4f183b6b1aeefa3489eb6ff3e9d9983" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string145 = "61ff953579f1bd83798d1038df66aafbccb8baa85cc8049efb78a280c09d9768" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string146 = "62ec1cf50d9485956704274b698e0bfc6cf090650794b8d6cc9a0d7b75638bdf" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string147 = "633add8af3d5bde70aeb20247a4d5fa4f19a93f12764e216155a94e026937f6d" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string148 = "66cf5a1681259b3e801b8effceaa210e4c66eba58c9ab260ddc7463474c637e6" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string149 = "671ebf4a6d78b932d9544bb7c6469d0e08bd6124462f5b94d90597b82c5579b5" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string150 = "689798d97c80041b0d42e4db12ba8d85b30889fccca42e92faed8d5151ffc91d" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string151 = "68b1bf3e1cd96f1ac58a0a90b888a2f483b6996bc46d61dd4ae630f23dab93a1" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string152 = "69840aa0cd9ecadd2cf19e7a52f429e46df6d2945022a0ed0186343d10706094" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string153 = "69d3a5d9b30baf4ed4b24c664eb1e787647acc8e9d631f2498e934c9431c829e" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string154 = "6b2bc6c1948e0462eabd40d92b7201d44648655679fde260454ce7f970d78b23" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string155 = "6c514ecc4155806aef7eb0a913cf4a88214e20bdd69694ad9ac5c565d588dea9" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string156 = "6c9c712e0274ee0e79c0b61f59b8bab9670afc69b905c987c6648da76220abab" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string157 = "6d9f0234c1022ad90c0ec7837dce7d93df645d7aac58c6fc75a0ef71450d477d" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string158 = "6ddb4ce3d13cfc9003bd4351bfd6ce9ad25d3cabea52e9a7e7b9ac1ca0cd6605" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string159 = "6f12c2f6c1d43cc0cfdbd2f73917a227ebd507de82e3d45b6ca6de259ff89f0c" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string160 = "6f4ad87a95fda2c0a77122b77942d54f688b6a355f40b256578cf7e8c26cc5f1" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string161 = "717500a496b76ffa5205ed4dd9bd2ef79da659d75e1d8e98efb1b2ec8c224509" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string162 = "71c807766303d5e102509a7209831660c1c947db0da3d3c1e3f9be5be5d5ceb3" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string163 = "72cfa26b9ac9f6c0e9af071df88f52d526b6b1301ab1c3e7055416e059ba7926" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string164 = "73857ff880d961978dc2b9d183462db429be5397341f2d2e8885c8807c0919e3" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string165 = "73eb5215f2d0d3a768bceff7c385d7cc3cf2cd2d0f7e8b19ceedb9a5c8b35a05" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string166 = "74173938c4040e181f011e7e2f6cdb171244c84f96517d0392a7759bf7d72f12" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string167 = "74b61c34014cb422b0eee3c53b32cde42a911c53bdfe80e074546fb26376628b" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string168 = "74fbccc09445b0aba5eeccf05da49fbfca37508e6ff7e271dff3f5e6d78341a6" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string169 = "75cb7ebd2e1f98eb7e97929ed659acbbd93b230bae532421a9b5f17ad13cdf86" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string170 = "762089017bf87803b74509640cd7affd14e56e96747cbccfa324c4f766379470" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string171 = "769239f45299ec58cc7328bb467a8bd72ba5e3f37b73ebbaae6915c3460668c4" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string172 = "76ccaaf7c67797cd5a61ce1855f5d8119c00970383b5a0e138b919434c63a0ce" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string173 = "7737f7230b1f09b12b877710b8add003b01c59d51ac734bedeb283ef686010e9" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string174 = "784e6ae14f95b6980d03543b36191595f5f4087f00bb7dd75086ac86c8148923" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string175 = "786b267fff4f1a5d826418d127432d495d21e25eb3261c0e6c9f2db18abc5962" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string176 = "78ddbc63bc64a5f1dd67be4a5ef8ee94ec59c9492fabe3a2b96eb115f755be90" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string177 = "7903eb393533b1ce51e527cae1ba3c4da6752f87d2717c3984b39228ce65a028" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string178 = "7a3c9d753d8905987a2cccdca22a3dc2e1002ea396574c44cd38688bd184c9e8" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string179 = "7ba37f26aaa4de6fa3f0b1d77eb2d6b0f14f7df9acc8bb7ff8837cddb8941fa7" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string180 = "7c826148232f2a27362b5da0e089ce532476f5dbf66d57a95bc1af88aaf890ad" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string181 = "7ca86e21a7433649ab9a2adc49dcdd8a6a415969c16a4158bf32cb06dfa1f8a5" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string182 = "7e3a5a3901bc2af3a00c4c3e2296f0064778b5be47ae0d0b2eee7afb72d8b3d8" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string183 = "7e3dbba1c95060ddc7fe1bf52e869246a6923e9695aa8d724feb8c5c1a5f8e37" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string184 = "7e7f92d6ff919fe8cbe63f2daa348d122339d1a0aac0883afcf799facd214810" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string185 = "7eb68ed7e2a9ca4802a0988d2d41cf8b859c00b8add791c52a304f434120c5b1" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string186 = "7fb420b5290c157897884e59a8a08988d5884f3fb586b557df48fe061b614b59" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string187 = "8007c76597a892e234a78716e7fd500ca28d278ade6e5d4de965b35c6fefc7fd" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string188 = "8023ad4a809f53faf76bc6c9b200e50b8145c561b076f6817ce22ab8b16ac25e" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string189 = "806238839177ab580463a61cc47e98ed9827f1bff3f9c501df53b51fecc84c16" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string190 = "807d6097fa6f16777eb54bc3be9639757e3dba0ca57c2a9d6b6b699289163df3" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string191 = "81e30731b5eb8a1e704c146062efd856cbfd37ceba4874d5907f84ac7deb59c9" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string192 = "81f47f6cd4d534902c6d146c6cf8bcb7e50d2b7b04d7402268e952278293347a" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string193 = "83d5b44bdd3d37cf3bc76b3e9e433c947c7917fa6fe8522d2e4421fecdfaf987" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string194 = "83e5e64474d446fb7f612d21968e4826a23f008e00110b199b35896eeb9436b4" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string195 = "83eeacb73e1ba4d3eb4d91887fa338e27c3ec91e283d6cdf2522322449b5e8ab" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string196 = "845b979d93d58f985c1b6e1153fcfc12732c4d28a02cbae528cf106e55cfb93a" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string197 = "87d71be6639e0c89794aec6646ca5894c4be239c61462b4a8e78548898c553e6" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string198 = "88d829d4560be8d3c7323523d84320910daec9354336166d0ebba78f24032819" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string199 = "88e1851d5b2c7725bb5e2cd08a45077496d207d8e04b56b35b982d6e32846f20" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string200 = "892405573aa34dfc49b37e4c35b655543e88ec1c5e8ffb27ab8d1bbf90fc6ae0" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string201 = "89928c5882095cfc598c9479d2f5e7d9a41c3581fc0fd447237d79a310c305cc" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string202 = "89b153d078008da7bf1d05f4f2f6a655f2757472a9275e2895b311d44dfcccbe" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string203 = "8b8c267ddc5eadfb6f8de8bf34fdcba33016bfad0111a38e804f328d4c8c07ba" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string204 = "8c4f57209e64bf6c59a9199663c8a386fc03f893d7f05539fb0f9b4a73420918" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string205 = "8d0b5ca232aa2109cf7fbc5a1c046d1836d4554e8a572eb41f8967f15ca7aa91" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string206 = "8f0b8c0bc95134a4de6b0e1843e4f06f895a86778eaf0ec4de037827e14a75ff" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string207 = "8f72c5927a494dd87792908f62fbe8860e2f0c10c1ff1f622c5a484fcd78ad2e" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string208 = "8faa1748975d3557974c240d1f30bfc6f100a4ec3a9c2f405c0814dfd45fe384" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string209 = "905332f37ef23c8e8313a76e89ef3388329427c9136de626ae4f7cc5876c584e" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string210 = "92c11dc911a2dd27aab2a607f55135cfe30da9fe68d3604b2efd798faf640a76" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string211 = "932c73eab9396ea8804470d3877d844f29c2e45ea3826792e3fd40e2c455b34c" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string212 = "935c0c6c3eee84d0550edaf387712dd24924d94ae327244ae36611c4ebbeda49" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string213 = "94e9de0688840caca05e9d77b64b3c1e5ff94d9c45cb5715395d419ae09c7559" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string214 = "95124c125ab9185d2895ee5462d67235f7391e79288ddef6f3ffb3c918da6fcb" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string215 = "9590b53e0fb6f32911ba12dd08129a125fda9f2be61225233d851570655cd962" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string216 = "95eadd9a35d11abd017c6355f1b1cfbe7b566cee62bead208c64931c25f610e6" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string217 = "969f92d8c70737c5c3e3bff8379c3d432188ebacd379428b8a49def2ca8fd582" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string218 = "974aa1a4d6ec99c9db926c0d46c76e7158c5d554a1b5a46cc36620244a27f39e" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string219 = "974b582afcd5cb78733171a0b1a532b3d06203f5f2731acfe3958e68716c0b3c" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string220 = "9919f925721fc891959663daa9b9f472f75d97396bf60c1baf9ee3c10a89f73b" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string221 = "99833f7e6a8120d3f1df7098d8314d6469439a6dca2841ddeffe570e1f14bed2" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string222 = "9a2a18d4f18f7a64c52cfe036a86f5bb2f7f7770d70031a8773df3856895a082" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string223 = "9a560a6c7ad81192188dad3e3eb2cd752f552739876009f15e8aa31f8be45f39" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string224 = "9aa60c69492c8b3ef312ec4410e0574eb054cf7ca9785f7c4d89d83277143785" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string225 = "9b473206df119def590d2f515c19cb3db7084c1d3a2ec1199313f551bd6013ec" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string226 = "9d0597a638eabb7fff63dc41d6449d47fce11f4491a703d0447e78d53387fe38" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string227 = "9d0edb290dc290f8cb748123558db11a3477269f810618a86ff8e81f30830e08" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string228 = "9d1fb01df8a856d1bc633277add91aedeec15f773192a8733de3ed747784c916" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string229 = "9e68d5982934294b5ef4bd570efd96b170d6a2aec1507cb4f248911da72380be" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string230 = "9eb625cc9e117d567ed568453ab0e5d9d1c9af2584338fb78640a1fb03dcd1c1" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string231 = "9f29ce88a53096c66bdd2dcb1b1e04b305358bef7aaa681a5fa8cd8ef406e63b" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string232 = "9fb81c3c3003985257be77b5ff0e531de79ecc35fc84c98a92a59e8ca88e25f1" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string233 = "a040131b51b4e124e4ac5a2cfa2e66adf3f7f279f98c86359870285bff228f42" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string234 = "a2031a3ae2df3902ff26bfeff68f5c04a852e0d815b8e8dcbb2085f08b23656f" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string235 = "a26411f870a108af946d0b0298a2af36b88a3de21af299e71211e6da101f8e41" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string236 = "a2749791478d33e10f88bba9c8191f42614e8606189f3a01a1406a2b47227a79" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string237 = "a4c9bcf5a748e432e6ae84393c4d174d7f1b7cc6a3e7308183ac829970b73e6e" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string238 = "a66fa8f23507c11444e52e58ea00e3b38e972a5d95fdb51a824967fd8183460a" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string239 = "a6d7077ea6b3c4aeb393c266652682661f77e334b1809372eb260f9d24d2e648" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string240 = "a70208a1f564cce41472dc8e87cd9e4d9bff7feb6ca03407282ffdd935967ba3" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string241 = "a74c5c5699517281aa37e2b00acb36a32b33d7d7c686a41c8d6fc2a1594d3611" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string242 = "a75a10d43c1ec77f2e59232d6c4f66662d7d3c9d28195d3b4aa9e201d0d28ae6" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string243 = "a79bc1f4c36a377d1beb707300e47c0ba6c3bea953f77f6e2a0435a5a23f1cd3" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string244 = "a7c7396da9d14ba531ea5c09d8920ad52eb2300b2d48ed368413cb77c5035ce4" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string245 = "a95f17316afad267ca57989a4480fc157aa50618868cb19defe14e45cda7e23b" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string246 = "a9aae83a121f855ea420850fe6bb8b01e80e3dcbafcb50d819cb2f71de8fbeb7" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string247 = "a9cb54d1e2377be31945692f6206a98056419b6ca641a3e79eada2a259e22226" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string248 = "aa67b66d9c4124b52e572988493b78cda3ff438dc27988ff30338c3f6d38e34b" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string249 = "aa9ef9b244e7b5d88f24211586a2e10d553a7c80f9a6d17a3d5d783d115b2f47" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string250 = "ab4b3257fd667f9daf4cfbe54992b99c378a1a2e6922fe5d955cdaca6da99f3b" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string251 = "ab8428de3f3f1eb1fb54c974d71296373466ccb7c9bedef96329d6fbfcc23947" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string252 = "ac1e2d8de30ae0048cfe3ae27fbddcf3e16e38dcb33d9b83c16f32831c865219" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string253 = "acd40244ed0a4264f5bafafbf9ca8e4b3813b27013bce2c550cd9f5e8093c8b8" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string254 = "ad2ce18715d8811efe3071d94d6cac4b1f0a60dd4e6b95c0bb43e9b9f3dc2921" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string255 = "ae50c71517182c9773bb138745f10a643b1215078ede439b2b3adb486a9cfb14" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string256 = "angryip/ipscan" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string257 = "b087a02bc2325dcbb06caa40e7debe301dea47b89f1e4a875092835e056f0b73" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string258 = "b0a1898b536d811f388b3fddd94d50c8bcec6e87f11a7c36e5d4e5761563eb4f" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string259 = "b190ff95d6d155e9a49752a555ca8ba14fe9e40156ec8cc5f8bcb6b0674cb80e" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string260 = "b31e9e186194897b6b75e122c5ea4bf20170a485ff31faf312612514fe7b92ec" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string261 = "b3b8e7d50a413a441df3ee1d510d3a9f537f9bc3a8da6119814da8da34940e64" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string262 = "b3f9f99ab501e8c40099dc351b2a59281e6a6b8117deae1e0d820ea70dd6a041" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string263 = "b411cbafc30aeeb59c69803b5f962f87a653fdf4a4a6f4292ecb6280978c0cc2" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string264 = "b624a1f6b4582374715c11809ec8cfc7f8d6b15ee426b0027357377eb5e250a3" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string265 = "b7c1564546c8c57f4c1581d8473ae7a88ecba2e2a114178f8862ed8a15c93e16" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string266 = "b855b843211e9604d22362e14906b73b7016f230b11aab67047ac8b4e071da18" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string267 = "b8b12628c324cddb1e1a464c1caf2597b66ce8f5f1057ffa86c1fe7b1c241b40" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string268 = "b9593e94892849b50e819c070843639953a69917a9069cb603433b3261519be7" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string269 = "b9723ac6913ec711c25f35ae45869af57f3868b690a8da331ccbedfcd37ca68f" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string270 = "b9e13383878ef7999d46b18b41d6699ce5c406af071ec849235bdd103025e3e5" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string271 = "ba8bf4dcb9e12c6a4abc64205fe7e07ddf0610db4a6c536a550125d597add25b" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string272 = "bb1ce1e7d92f6ac0da1bd1b8cee56d6139b9dc41f5821e58e7d07063805e7b3f" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string273 = "bc75191718b8556c1c8610987285d98f7421044d7be117252d5f35516af3205c" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string274 = "bc7ee01c3d261a0c0a63e250513aa2eb28d7f707570c8fb507742fb125c5da07" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string275 = "bc811e6d2c2df7fd2826ba0545a5a27f53d6da1420abfb8ff5ff8e0427a9317d" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string276 = "bca3eca534819386df33cde502bcbb23224dc2f814979ca580be4ff2d4c80067" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string277 = "bcbae8d4564f1c0933331c5e4c5b779a72d889504155e209e2aa942b963160b2" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string278 = "c049a837cfa5f098e27fbbe5904daa2cf3d21e6ad51b662b2ecc723c3abf6c6a" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string279 = "c08c98dcc7973d70b4024299db6c96acb6ba060749af54da45724b6427d0d897" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string280 = "c0f307cdba8e36664c10d7d7969bbd2d0e670503f33ae8b2ed693ede0f12f5b9" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string281 = "c36fe320b5868ebb899a79c09b3c7de43c887e00ad63ed34df6c47cd8fdb2919" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string282 = "c3c3c9668033f2f2b272b6003bf9ecb9d0ba77a04f5dc0fe79a1d4b7a1f31366" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string283 = "c4776bfa13df65546ba20938f68214281a2d1771ff0d5e89542e28d34c54933e" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string284 = "c5063df64bd9604d8cdc0d20d4a1eb2340425cf7a38e126fbe45f3e210a1b6a8" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string285 = "c6c3d2c485f517a417ed0303ec5af3888dcd3f31a90f7c0d959f01f4a540d61a" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string286 = "c7304d8f23a7d129d30e27955a020357518164d01e60eb17b0db2768ceed435e" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string287 = "c7e26e0a8bbe91d86c363956c9d5d4d32b55f195c9a4970cfad4df2a07853013" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string288 = "c8a45f4e2b59642d67abcd63f8c764b3b8fa2713bdbb1278aae427cb31cde4e0" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string289 = "ca08f69443eb20365de2172255cc51e6be69ed93ef5edb79d870952fd68b500d" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string290 = "caae7a70d2fe9e94e7870ec50278b0c4a115e7ffd6c87e7c729462019f973024" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string291 = "cabc5f4b4dee64623a9a8493bad6c1fc6db5216caa5c904f78cc82d1d25645b7" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string292 = "cac1286a56b2de1195d3b79ed029e68f827a1d4e8da914097dfce64584e407d0" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string293 = "cb5c6641c926bbcde9dc6306f2049aafa148ce393b974f2b7a0d7e0eafa811f7" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string294 = "cba592d413d8cb3d09989b0b7693f3247517590d2e83329d4ae5f5b407fffc23" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string295 = "cc352c90f7f771ad36e224e1b3357be8da3d698f8ef3edc2ac4999dd843a5071" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string296 = "cc5f8c886d8fccf6571caa4954c7ec3e5ded2e8de3c06da6695c8ea755021cd4" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string297 = "ccdbf9ce861c5032c54faa19c8addfb6a113acfc595851a4e3305d946f2abef5" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string298 = "ccdf8f148f9d2245383d69a5d9c7d4a5595c2c7c31416927ebda1e3bc1d33941" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string299 = "cd8c433651e8c1f9442c29ef575704a9a81168dd38e56ba882c02d1aa372c545" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string300 = "cdd530f38141348a294c13eec996195e8882d00d2ffb2b0ec89f58508fc3634d" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string301 = "cf700fa504e99bf418029192fdfe571eb19338f2a9053bb81ca082c714cf59d5" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string302 = "cf89753f97f44100d17ddac620231af952e70cb3f4fc02f410d3573be06b332e" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string303 = "d1a9af4f13225a46916c1d71c7645098a589ee5f9270aa018c915153c076b76f" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string304 = "d21feb81faa65f44ab7c0c4c77d8e2fb012168ccec13b6b3aa63662812e14023" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string305 = "d252cafb581626c5cdf72411d66eab796336cb02f4813b11ac34f628a603e482" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string306 = "d2ec114cf44c9e15b158efd61850595daa1bc199732cb017d32abc19d66d4f9e" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string307 = "d3ae15d4a9cc5c19e380cea606bc247b3765f93928dd7ae2d03e1f0a4f623db9" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string308 = "d3fc4d5bc4e176a51422c1cc9fc882b6ee646b0aa57dbb59feb42fa3c85783e8" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string309 = "d4016a747a083cd6a02f81fc980adf7b318c625a00227ef9a216706318800165" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string310 = "d5c8fbea45f7ce94a5c4753e733ef530aae702a90eb67d7ac00faa8a9e8e9024" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string311 = "d6430b77260fe3cd4fde6422317cbf232f7af5e29bd81267d10f48b01afec850" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string312 = "d6d55eb0eabd43a50f6de2f77b7b67e2136578e8d5ab0dfbbefe21bda3937e91" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string313 = "d8aa3176d3cdb0deede2becaa1c383db0c78404f829c2dd06de86736fde68a09" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string314 = "dbe98c8b66436859514f07786c6903ca2805083615201adc1d1d63d1fa66d14b" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string315 = "dc1c0ca64990cbd3f509f404f6cdef395895bed206de7d320052267586bdf416" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string316 = "dce52871edb60f241f17fc6a43f236ab53b4b42813c1af0de929ec261eca2637" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string317 = "df2bca8190a27477227f92a6825dce00fda7e2f5c2a2a3da67638b016ff62502" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string318 = "df331b6bcc463f2caae8c4d892f473e2a4a37a8970cc8e38a776735d6feaa140" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string319 = "dfb3aea9e6fe5eccecfaf6e280416d9c93b0b2d89a0094cb83e19002197c851b" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string320 = "dfca25f7d51972cf38fe3340b8e9967c67532d5bc6d776c0284b741433c94184" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string321 = "e1c6aea6094d317f351d9260fd6ea1a148f8a102c919c7067e2d39cd1016a8f7" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string322 = "e1e0d3e30646550711722e8794192b05aa51adea9e4e02941ac19e67fbbc4c0f" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string323 = "e31519c2fa99c4739269b273268b45293a7f02b98a71426028cb37d4ffad95ca" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string324 = "e37228d7dc5e4766d9070bca5f0d616ae04887d7f6ee7b30cc8ea5a0190c7441" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string325 = "e58805777cadba322e4e1b6a15969b34fbeddd0e473fe043f6fb976e71652b27" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string326 = "e60b16e124c84e2368a0bb9dd85a282a163ad1cc9946745ab14adcca5075d13f" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string327 = "e63896070e742e2f06c696a551b5cbf082acad80d48391b42cf2d040823793e6" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string328 = "e6d90023e2588a3c52798d2bee864c6e87066b6e8867b518c4f59c75a4d60cdc" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string329 = "e6e45b8cce5e26017e9c4033b2c9d21a32a30c850f13c39095f8aa2571241c81" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string330 = "e746327fc595317f4fd949c7e46bdfcdcd70a74c9402dc65fef045ec8a2c621d" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string331 = "e76cf4f44dc62c008bb203fa88eb3e942e7f28dafe6a264d2f5970a8befa142f" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string332 = "e90254549780eb809f13048dbbea4ee473e0ee4aa0d506d89c463881cd6351c1" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string333 = "e9b267aac8adfc7fd11d83c4e6a7efa9940c338207da988b2429d61764fa485d" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string334 = "ea78a37a389c32e94aafe2115a8d75948b21cee204a5a89b64febd9f18932609" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string335 = "ea8792c7e11cad017c54c50f880e487f09581fd2d7f24ab453118ccf35716357" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string336 = "eb272642328677b4aef6922f2d845fb6d3e6ba3e0ce1f6b10867c9726f6076a4" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string337 = "eb6aa78a64ba7c6ed9341855d3aef5742ab13948b6cd445e9c715260f8d10dcb" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string338 = "eb91b66cced883e4445f8e26fbf33689c82d04f5c736866d08d00847bb46b1f8" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string339 = "ecbbcf4b40a507200f72493409d2a0fd22ba7958fca6121679a0b9c2441001a5" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string340 = "ed8e23f58c3539380673c26d1ed265f703207cc2866f6c3e9e004859a0a559e5" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string341 = "ee35e912fdc0dbc8ce07822ab1899f7f4b85e8113e3e1b743b0a303924cd6b22" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string342 = "ee95cc2e9d7a6b048cc0637fab30cee273ee5b0fb144759b25dfc55f5f5434f4" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string343 = "eedf9170ab629a168f92f914dd1e633516ff6b7f8df56b1f459a08d906a29e73" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string344 = "f63a9a1bff8841613c2f8c0ba7582631b89f4ee7cb0d03b59daa806a8a79ccd5" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string345 = "f7bb32eb31cc17a691592f1944f8293b247833f39703e7521f92ca230bb6c220" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string346 = "f839c9b6fcec3e97ee042604a00edddda9262985a6768a4e16f4dac8eb8d8238" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string347 = "f8a6470914148f0fc254ea773d4dfc870b1324953165fb619b2cac985418ab06" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string348 = "f8da6811a00fd70fbd31ba8532cab47c95d53e675582364cf5d6fb9d484977bc" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string349 = "f8def6c6c62783ce0b607d4bb55089b8083f052e1b2da4db1708dd494964b123" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string350 = "f9432ce52449b2bf1d0b92046f1ea0dde1f306740533888c2ff3f190f10be1c2" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string351 = "fa4cdff048c350043700888dcb50a6a5fa1e1dcfd24a86b1942b0d378912e0a4" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string352 = "faf8cbecf71ca34708fbd7cfdbda9ca81476a29f7dd8f58e1e35bc64b58e8528" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string353 = "fc4ae0ea29ccdbfb58ac8ee898beae752e1a3e8528e94c02630c9bf34637dadd" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string354 = "fce6c490393cd886beb5859fe7cecfab805098c1f2db88c290209681ee53bf50" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string355 = "fd68dceff58851ac4a8ba8ad476cd72f3fc0b3e62ada8ee355157f677ea67b07" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string356 = "fda286756bd8b976139dfd1dc8e80532af74d8b628d69850d29335dd6d1a44dd" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string357 = "fdc0f0e9a4cdb1f3533ea2bc643907365556bbb7386645bb143942e60beefab4" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string358 = "fdde0e3af2596af6e1952bf4fc050dc4a5bd73c2826775b758fcdca93f91c134" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string359 = "fe57ef744c2f42fa72573f27e8dffefded238722eaeaeecfcbaaab239c4a07c4" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string360 = "ff82293d001f120a624d0b71dc57432f4cbbd813078d4092685f62246b12a918" nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string361 = /ipscan\s1.{0,1000}\.255/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string362 = /ipscan\s10\./ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string363 = /ipscan\s172\./ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string364 = /ipscan\s192\.168\./ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string365 = /ipscan\.exe\s\-/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string366 = /ipscan\-win64\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string367 = "MacOS/ipscan -" nocase ascii wide

    condition:
        any of them
}
