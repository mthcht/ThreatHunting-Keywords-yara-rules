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
        $string2 = /\sgost\/cmd\/gost/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string3 = /\"gost\sinstallation\scompleted\!\"/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string4 = /\/go\-gost\/core\// nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string5 = /\/gost\.tar\.gz/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string6 = /\/gost\/raw\/master\/install\.sh/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string7 = /\\gost\.tar\.gz/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string8 = /0276ec0ea830a61275437a98b81224b95712ecac5a7b9850bcbf2444ff46e47a/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string9 = /047ab1af44f368297bf21b302a2548a556ca4e6c6b721940954e88f43d1cfba5/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string10 = /10168a998e30a4f0d0d175f1aa2d5a533df3d69cf206f04f7d2686afdbe0949f/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string11 = /110ec720cf51d05c3a07ee73534f4c949644920a4760f1ceb8fc09e80172aaf0/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string12 = /1ff7731d1b7af7110f27796e0fecb551cb5067030aa7d87e333d46f3f57f4214/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string13 = /254cc9b46f64f1ae8150c65632ce0e749dd894b20db9d39313e8030477152add/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string14 = /25dec6e071fbf271817fa34a76abe61e41e2cb27cc52f25d78488340ccedd190/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string15 = /2c344a29ed1d2107554b83137bdcd87db445be709b089520282945d21c755189/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string16 = /2e8bd529f1452a300c60d13e57b46c35d1c3c2f8b42a4b03ce82fbf78211af49/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string17 = /2f6d418d6b2a974433581cdb959f6b0f8f305fa48c00ad44dc19a9d7504a4c5f/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string18 = /39f119574d66d00a12ab7ed202bca6e41204bf838fb5f58ca170bdf76beaa445/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string19 = /4363de01f1dfd6b393f889bb916128df95a02bc1df2c294e28a48bd197a685f2/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string20 = /4549122ba17882aaa89999d170ca7cfe4d2f4d9cc9b6c57961abf276576c9d42/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string21 = /49e7c86340e6930402911320150a14e5aad183efafb8b56747d97a8a5469a187/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string22 = /4d7fa7fbfca88ec9adb9e227f4049a544acd312dd5c3a4d4f936e053497b7d65/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string23 = /58553520765d913785914cb41570a76668b07e43c40d313841f7c03fddc899cd/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string24 = /5babcba4005adce8f620995f2a56e5d6bdcf6695f52a539bdaeaff889d47e8b5/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string25 = /5bd56a5da478c542e8265d5fd15fe8ba90f720bbb6a2649ea6c4ddd5acb77d85/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string26 = /60cd72287033962ecbbe8c27c7cb84dd7aeabd183a338ca4195a5b5275138076/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string27 = /62d7b075905119d8ab637df0f4348aca30ede58adacfe6d05cd3951db128ba91/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string28 = /6419610ef4957f7d62fdd16b22764a68ff694a612449195b932d169f523ffe20/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string29 = /681f20b796bc6b59048b2eecf7a05884cfb1ea2464a14364f0769a10077bfb5b/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string30 = /68715639afd1f47089068f9de486068471fce5fca4a07aef888f960b73b09d56/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string31 = /68b38ba64f0639f6c5b7c95e2d19676574cf9cfb2034748c46d89811546f3d88/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string32 = /6eba09a7e386379e173bea81ca5de348bef4c0f024d2efa963ab8d3bb8b37a8e/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string33 = /7455b514720dacb5dadbf5c3cc1a69614ded8375ebe23daf0778441af6da907d/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string34 = /79c98d35d02ac92c72aadf48a1ca55e2b7afe5a41ad70e5cf0467c50a84dce22/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string35 = /7b23bad83e3921e1d9e528b69b7d643b646231e5b736f8588698326c527e31a7/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string36 = /7cbcaba89fb2dfe22cbeeaf2426379560f015d49f4dad0caf2cd732146d96b84/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string37 = /7f27f414ebe84f189adc68a963c7735d4cef34307a19cd0c21243ec202f9f456/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string38 = /8579d38432b7652643a84d0fd7edbc78668ca3f91ddc1d78ee8840a7a35fa9b7/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string39 = /8768fb4f5c0829e3ed696af614ff761ca72b5538bef2073464f57eadc76f5ed4/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string40 = /87a25f52f233c1176eeeab554a2941f1738a9e86669fb7febe8155d15ddf5530/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string41 = /8a1d6e1d9a8494a491c1f2fef92f0243f4d39406fa159b4ecb45428148fcbeb4/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string42 = /8d59755171b977af9ec836990ee55a4d1f17873d7773131267b774b14d121fff/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string43 = /8e3a219286ad2715712ada61697d622cf5eb597a05bab126546101cc48e0991b/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string44 = /929081341e76319dc5209b58611cc5304b940bed099b2b63589534d1963afab7/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string45 = /92d2460414d1b79ae54466442eae7628bbb343c70948e8c2f9afa4d158a0f3ef/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string46 = /956c78246b4873877ac8e1a0ee7eed3ff7f9068826696f40f8a0577c55c8f184/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string47 = /96c82ea18a4d63d57c4ae10b16e9761fd7a29f92e0704850783768f561e9b85a/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string48 = /96d4cb5937b2b5a38dbe2721ea427ca64ffcd745ecaace820fb4daa1c322f696/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string49 = /96e1cc96595bc8486dfef57f78f680c49e7b19d12649d43fc6501d7a599b4657/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string50 = /98b39f9470d2ed0cbf458c04e94dc5762c8b72cf4fb51ba2bf641fdc4462668e/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string51 = /a10f6df2968d892ca277eeddb104dce0bda26aaf47b6a29fa37f6ef7b9b4b330/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string52 = /a49b64c34c17e2f94a789517960f3438cab8b92f8e21560320be9ef68065c9fa/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string53 = /a5c16b96d4df537cdc307206b955f7808b58fc2fb425a327bcd6e0bccf95c1ba/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string54 = /a7a2808a64b5ee630b2ce13597623de03ca5d7a27870aa72f3e0f8156f20d10c/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string55 = /a91962e86f2b0b0a3a75a097ad056c5595dce4a66a204d15507d03da6eec699c/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string56 = /b19a810320e3d27743080c6732d3ee8caae0c8b747df6001b81b0a1fb226665b/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string57 = /b6f5c4dc870fdc69d0309c5d5a2a5d48a924a5c14a62b8a13228f071749739b5/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string58 = /b7e45744a48f5a5db2177b70a0c6741909343d2393045204ebf6c740c50e1de1/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string59 = /c3d703c8e406f542bb9688a3e31c8164c8a34ff99785e256b2f7da8ae73a85cf/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string60 = /cd84694d8b390661c5295f76a523381daaf840c0b3ef16cf02b11086ad8d4028/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string61 = /ce360e6f1b4a634b603f8ac114e938c057bb1cda5141a053d83e16bcfe08e373/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string62 = /ce523561aafdc54a24581460262853a579dfeda9653fb88bec95e3752a370118/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string63 = /d12a87b47c9213d80b8dfe9626702c953ebbfa92320b01f5f8b42a520a232537/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string64 = /d5257c716525f4cc42778285074e6425b22a272333d08cc75fa27334025b4c90/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string65 = /e0955f1c4b9c89c926928109a080924c6400136bc2bce8d673ebf42c1d54d510/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string66 = /e2d664ab3604b082e17dbd728c89bfdb82b5616f92defbe0cec24d94674c5818/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string67 = /e40c9f18d7f47c131876d6ef9a29385802e0d006e75ead9906a980c751fbee16/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string68 = /e5350eb7c85f40bd5eeb5df8b3cd58805d39b2469a1c1c9817957fbab77e9427/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string69 = /e59ee7929f1c67c3aae6aa1f31299e0403430e7f25aecbcc572e19db79451d96/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string70 = /e671c90f050cc03b06a1c976db31a1f2f1a498730c63bb2a29d92c9e47af5f66/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string71 = /e7ff1472a7294417e4f1dcd1c882de9f81f214b3f68f34ef4b8adca5af593c6c/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string72 = /e9ff51cca46583fe8f3ec4077fd863edb916e4d170d491100e4e35d8fa782a14/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string73 = /ed19d0c0a65e0eaf321f86f95c1026fbae834876a8431d65609937e56e240ef8/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string74 = /eed97f810223bcf85f69b84040fd3e44e4a4569b4fab06da412c93fed71aef02/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string75 = /ef1d847561dc29afa96b2e827e7c9a94facb9b6aae2b09ddb33c3c50ab581ae2/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string76 = /f0d19d73955298f2766e55ff49347e31b2482a3bcba107ccbe38630b1aac355a/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string77 = /f2f4b7576e0e51425fa90f94f272d0163571f90a0ecb8549f8b97dbf89c5255f/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string78 = /f7f52607771ce2dddde694ebeced6e2dc438a29c8b87cfb93f125db4e968107c/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string79 = /fc258ceabaf70cc28b8519a46a8045cac406d275707942f88e952621c6c382ec/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string80 = /fce455e607e33bce8fc0f29bb1bbf34e7a886c39bb48995ee3af25a91f2a57f9/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string81 = /go\-gost\/gost/ nocase ascii wide
        // Description: GO Simple Tunnel - a simple tunnel written in golang
        // Reference: https://github.com/go-gost/gost
        $string82 = /https\:\/\/gost\.run\/tutorials\// nocase ascii wide

    condition:
        any of them
}
