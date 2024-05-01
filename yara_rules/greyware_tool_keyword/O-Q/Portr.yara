rule Portr
{
    meta:
        description = "Detection patterns for the tool 'Portr' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Portr"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string1 = /\son\shttp\:\/\/localhost\:7777/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string2 = /\sPortr\sinspector\srunning\son\s/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string3 = /\sportr\.exe/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string4 = /\/amalshaji\/portr\-admin\// nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string5 = /\/bin\/portr/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string6 = /\/portr\.exe/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string7 = /\/portr\.git/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string8 = /\/portr\/releases/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string9 = /\/portr_.{0,1000}_Darwin_arm64\.zip/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string10 = /\/portr_.{0,1000}_Darwin_x86_64\.zip/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string11 = /\/portr_.{0,1000}_Linux_arm64\.zip/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string12 = /\/portr_.{0,1000}_Linux_x86_64\.zip/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string13 = /\/portr_.{0,1000}_Windows_arm64\.zip/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string14 = /\/portr_.{0,1000}_Windows_x86_64\.zip/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string15 = /\/portr_admin\/.{0,1000}\.py/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string16 = /\\portr\.exe/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string17 = /\\portr\-main\\/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string18 = /04aeff8ca9ced185a7f1e860e046fcfbf47b5345d4480b3015937978fe2d2ecb/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string19 = /0927710fe2ab1e73a1797de36da9ada6322b8ac8ce473fc2db3a8b70b3ce141b/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string20 = /0c6710b58b9054fd232c624dae29020bc765c962ae095a3eb53a0981379689b8/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string21 = /0f3a3f091d06f67f44077711477c0908a957f161d178d9ad8942fee864ed7a29/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string22 = /1350cbc251898cdd6fc09f6ac24ff69b68ddb95ea71379dee9f598a62b484430/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string23 = /1c76ba5931eda89deb05158b1abbac7f740a594509f3620c52fa66287a5e7a6e/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string24 = /1d57d63ec9e3ec8fb3b527132e6603c81d8bdea62141c25c29e7d9e24b026e9f/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string25 = /224de67abbba2df8eb17aa567bb2b3be029ad21e4203692b6abb73628e75db02/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string26 = /34b5107c27cbae4cab4addfece8236d168102d7d6cc3ee93d29bf4d4b550065c/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string27 = /3f3be7d94aa91ed9d14a8c8f37413d2a3057c0a2758d579189c84904285007d5/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string28 = /451d8fa3adce80028ea451e1ddf7a185ea4a3329aae156bf40fdda5d1ac60c84/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string29 = /466869834998e6668cf4b7e73ed043c145c73c5a62e21d1bbf1ebf7cde3f86bd/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string30 = /48ef85a7f6eea1b650affacb62f046eca8a965f134482ff808e4a148a69e72b5/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string31 = /4bc1b107cd497c88dfbc262ff7bcae4e85874848df0435bb7ecb8334f23b19b3/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string32 = /4d797b16f3aa81a13bc1736b37e783336bcfb9a538148810b3d1ec8fe592e50c/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string33 = /51f4ff1014c223e9f936e13e8d053dddb16678c65e87b2cfa63cad36564d243c/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string34 = /54538a9a0676b8d5bb23c42250df271b736052c1f5b7168a73c14bc65aa017dc/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string35 = /5757b774c407cc8a6ce5f9601b244730635a30efcb0015fe454610850b14d38d/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string36 = /5b036a1f20522f45ddfe9956f4014efe311daed29a6888959f0822ff72da948f/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string37 = /61924a52c149b6ad50e462cebbdfc14c570293abdf1c97bddfe7c0c7580ada31/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string38 = /673de62a71e95d4b855f3a8c616edbe2b51f066625cdef9924c76a1f021a660c/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string39 = /6db7f9491dc7389e6f64cd4ae549eb3a304b1868309a40b7a175c0206c681bc9/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string40 = /6f4cee01855c127463f149bb94adc8bec1a5b9b19f8edfd8471002effbdd1fdb/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string41 = /727b1692111d8e799e8deb7f1243503994f08d71488805d3f8c35015b142a6b7/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string42 = /7a9f4a3bfc2a24075f9331f9ac21655b270ca43bb1845bc8f81e56943374a775/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string43 = /8027e8c3404952986b4323ee0773650bab81ae3cb36eb5f643b95c4f2c912ebf/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string44 = /83a82600aa1102569a14bb436c08b4abde68c4b47bd05934a4fed0ca8d187abd/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string45 = /85eaf5c3848e384ff88f16bf59f8d6e31194e01b2b8be58191de5a74d03348be/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string46 = /869df81bed2d14ea117e02aaff9894b9f9eac2b6c8802dd7be37eb14da8cca48/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string47 = /892dfce05bfcab969306a1034ef0fc0decc52d82b43cda8b6c395549c8ef1133/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string48 = /8e293b5a49ada7798b6d681ec267efecd5c6fbd12163ac13b042707b80f56c50/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string49 = /906172da211b4b657ad01652ffa8911d5add169b3eca2c77f5f1b79a178fe977/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string50 = /926dd1743afb553ef123f185b1ea1a0a463a25b4c4d0635142fa4ee4d5aceedb/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string51 = /97fc48554850cc143f262d6cc01fa415c7ff3bc517d2505795b70f447b0de993/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string52 = /9b50261daa62f2440c9e3ae0399615fe0b4d5dc807f4f9f1fdcd8a80bc0ab22f/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string53 = /9bf17e192c1d67d3116bee309c16ccdeaae36a68e53db5b555ccaf9455a255b1/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string54 = /a577a27e8304b63365699d0220bade895000da9fde1b29fdb0925292dcff0b4f/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string55 = /a7b789b5fbd81fafca5a5dca4671de13c6bf3b54b807c513d03bd1ee3f5290a9/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string56 = /a819a2e3e513712ec9dcba8129b7471aafc70ca6631561a8f6a4881a51ffa2c4/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string57 = /a853e1ad13c03ed6e28dba69cd407bfb2bdde3401c83abe79ab57a42fbd8968a/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string58 = /aea26b638e19ae54c752ccc0d9985bc6ccf0214a56ca5b2b26714feef2d95ac9/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string59 = /amalshaji\/portr/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string60 = /amalshaji\/taps\/portr/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string61 = /be21413da8a75c62583b1c9eaf5194f5853f5ee8aba7e67510069717a0fbfcf2/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string62 = /c3dcf5597629c40fa47791ba86420ff1322ca0adb6110b4fceec6168f5141ee7/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string63 = /c948e37486bb247fbbc9f20b5040a11f28f642f5760be9abda81fc979c9911f1/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string64 = /ccf830a3d9985235d37d82bc38432568ff15744e3772fbf52c947914cdd6745a/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string65 = /db73ab5dce549d531bd7e8ec51a89bf5040da07200e2834e7b652a0384db783b/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string66 = /e2ffe6675e592cf2760e3b9de2fd6a7c0298226b76f86f26b084de63ff4be574/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string67 = /ecdf4ee43944adcc0aa55f707711a0be5a0ff539792175195aeed7e3a860e457/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string68 = /ee64735aef9a98eff32fa75e2bf8df53b3c8312d85ca1d02e37c01d06fa6c47e/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string69 = /f1aa7c960a64c65548d23d2a77b3aa04844695174e44c7e04e0094190a1b8b46/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string70 = /f9ec1153b825b2a9bdb5bc59df82bfb08b7b85fe371c591f37c6748957378591/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string71 = /http\:\/\/localhost\:7777/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string72 = /https\:\/\/portr\.dev\/client\/installation\// nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string73 = /Portr\s\-\sExpose\slocal\sports\sto\spublic\sURLs/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string74 = /portr\sauth\sset\s\-\-token\s/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string75 = /portr\s\-c\s.{0,1000}\.yaml/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string76 = /portr\shttp\s/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string77 = /portr\stcp\s/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string78 = /portr\.exe\shttp\s/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string79 = /portr_admin\.apis/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string80 = /portr_admin\.db/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string81 = /portr_admin\.models\.auth/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string82 = /portr_admin\.services/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string83 = /PORTR_ADMIN_GITHUB_CLIENT_ID/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string84 = /PORTR_ADMIN_GITHUB_CLIENT_SECRET/ nocase ascii wide
        // Description: Portr is a tunnel solution that allows you to expose local http, tcp or websocket connections to the public internet
        // Reference: https://github.com/amalshaji/portr
        $string85 = /portr_next_url/ nocase ascii wide

    condition:
        any of them
}
