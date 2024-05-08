rule remoteit
{
    meta:
        description = "Detection patterns for the tool 'remoteit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "remoteit"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string1 = /\sremoteit\.exe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string2 = /\sremoteit\.x86\-win\.exe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string3 = /\sremoteit\-desktop\.exe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string4 = /\/Applications\/remoteit\.app\// nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string5 = /\/bin\/x64\/connectd\.exe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string6 = /\/connectd\.aarch64\-win\.exe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string7 = /\/connectd\.x86_64\-win\.exe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string8 = /\/etc\/remoteit\// nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string9 = /\/opt\/remoteit\/remoteit/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string10 = /\/Remote\.It\-Installer\-/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string11 = /\/remoteit\.exe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string12 = /\/remoteit\.x86\-win\.exe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string13 = /\/remoteit\/connectd\/releases/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string14 = /\/remoteit\/desktop/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string15 = /\/remoteit\-desktop\.exe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string16 = /\/systemd\/system\/connectd\.service/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string17 = /\/usr\/bin\/connectd/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string18 = /\/usr\/bin\/logger\slogger\s\"connectd\sinstaller\spostinst/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string19 = /\/usr\/share\/connectd\/scripts\// nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string20 = /\/var\/log\/remoteit/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string21 = /\\AppData\\Local\\remoteit/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string22 = /\\connectd\.aarch64\-win\.exe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string23 = /\\connectd\.x86_64\-win\.exe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string24 = /\\Program\sFiles\\remoteit/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string25 = /\\ProgramData\\remoteit/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string26 = /\\Remote\.It\-Installer\-/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string27 = /\\remoteit\.exe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string28 = /\\remoteit\.log/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string29 = /\\remoteit\.x86\-win\.exe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string30 = /\\remoteit\-desktop\.exe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string31 = /\\remoteit\-headless\.service/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string32 = /\>Remote\.it\</ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string33 = /00caf6dfcf353f66ed5c3937d8d12fcef79c27a845fea644c75ff9f3bfd27eec/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string34 = /013166fb62f933f2af2d9c1cc8207b66cb8e693814cdaa6d242e221be0a2fff2/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string35 = /0149c7275232b058c1da45542ec522561c8895a65ec6bc1422ee3c07a1276110/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string36 = /03b738de271f354a0aa9c1773c4561b736fc03991008778a50a352a54bfa111b/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string37 = /04972d8a2dab86aca68eed06eaec968025915df802e31c0f4db8e8baad010a2b/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string38 = /05852ffa6c718d4d63489c966ba8dcc8109de75c7390a6ef5fc1c8f1644a7ab1/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string39 = /058711652c885c5765e5bcc0b693c6861d3bcca0305474cc9da635a04898c954/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string40 = /0703f542c4dd1cdde9535cc7552b3bdb2a862904690d7e27f8c61a19f84fc4f1/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string41 = /07c29c4df1a2616348871ffd8ca04f3774243980bec8e37f093fe8c0b56cff9e/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string42 = /07cc0dbf5aedfcbba76d61e72e346b2631868e6bd200efdbec214d85a75417f5/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string43 = /07f70bf5e1e41d3ad989824ccd3eb652dd4f30d151aab605c01a05b9db74a2df/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string44 = /0a348d00ff8925287a5fb696c5dd5e4f66c4d8fad6f2a19597acd9dc856f15c5/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string45 = /0a6890a6e321fa795e960c77d09bebf620dba250274fb16fa59f1694cb2109bf/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string46 = /0b6e3bb9babf35f1580de0b32ba27a13e5187dfd5a66c6694e2e4713c49c0532/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string47 = /0b8c64aa6263b5ad20087692b6f1d2ae26875a1f3015aa7c8bb1f401baa59ec7/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string48 = /0c197d94ca78db1fa029238f944f822c1b90b6f976c569cfd31eb438b16acba2/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string49 = /0d7bafd96f7400a85372e15cfbb0e3d190701604903734e9546635720bbb56be/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string50 = /0dc1e16be2a13ae30176a34a2b31a93c3bfd49d1382477f096e3a91ba98826ba/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string51 = /0ed16e6b3d19d4e2c709a9fe09445939bc184499c020eebc07eee27becffb6d9/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string52 = /0f191947663cea1863ae366c895dead2e7a769acfd60bc22121a1d4866b821f9/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string53 = /0fbabd9468d07f89402193268bb3c1bfcc9c216f389e66cbc6eb75f3ef2a6dd9/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string54 = /1130109b30396301e05aba1303f6c5d27d6e35e033905469f45fb1102cab5c4f/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string55 = /11a7c6e09cebb1a12cf18f43562ead367a7f527fbdea3a075422e48ecabd9e31/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string56 = /120fdd11d2b0a7c94663024af9b13e8c0b557f9c0e1efbc1cb85fa2122552c7c/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string57 = /125344e96627208ed84121e1d5244eb4f4b58b6606a51aa0c39282866da8cf5d/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string58 = /1306f44ac242dd1382032f05a8f2ebf813cb71e0d8224e56455fbdb8cee02d81/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string59 = /1320fcd96e4908f3c2ee0e86b30b5c6da22a755a29c3dd4392027b00e4ef66c7/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string60 = /1359a52268613c5ffa6bef0a7030aad1cf409dba348b6b4fa3ab8d9a97d275ac/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string61 = /138277b4b2fb7da83f007207bec5df288dbc57ebff80d99c4a2d57eccc950bb9/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string62 = /1385144a41372d190eaf788b27372cc2bb258776722138c8ab3f1936e3bf051b/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string63 = /14b0160138b97e9183e570c542a566bcb68d815dc92761a9d31679a51626433f/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string64 = /1643e037fc61ff8a14184176044145d17ce1ef2bbf9fc7c2e0d1679853d9ec74/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string65 = /1797c1fffe28c7234cc822eccdc773487499bd62c19bd999095d5eb11aa18b58/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string66 = /184bc09abc6f6936a05c6ee49fdba98c5a289373ae70afdba2daa758d630593b/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string67 = /18a056d9fa89813c9e19f150cfab07ab374681ae253f4f7ce9953d4cad79bd2c/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string68 = /1c3116773feaf7723c98e6ec8c57dffadb45ed4dd6781133befb612fe40d5e96/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string69 = /1c6329a23d57e7b38b7ae061f609c4efcc75144cde1061ef3bcd2d2264b42dd9/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string70 = /1de7b243066345a7d95e5e61837e54cf91b687f5e064419d11ce6b48534d9a66/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string71 = /1e4339c6d4ebe8badb742b42ff9a336c9cbf4fca5d735dfdea67b7a9c598a297/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string72 = /1ede16af1fa680690f056d759d16a26bf527bd18d75cdd2d88c830b2a4afd980/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string73 = /1f0ebec30ded3a9df5a8e2195bbc891c339a092c8ac0f07233c8478c1182242f/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string74 = /204eefc73b55ea27b172fcedba0c3ee0615548663fd095839ba2e153c8664e76/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string75 = /205d67361d76c5f674393f0762515f32f005487d640751fb0cb67f81fa298ff4/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string76 = /206d0059cc04cdb49bff03b5d3658749b511257cc235b2944dc74b82a0b31a2f/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string77 = /20e6ac956f7f2b27eff59e66b04765a87cfdc9c1b2e30c5411a4a93b070813af/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string78 = /214f97a55b8eb353dca363203a6616eed9a47d5f7faf21ff77664df8f9a4523d/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string79 = /21af6d82b768b2311a249442c6777766b23a8d2f237a1905bdcf5457dea65182/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string80 = /222ba94a96c4cd53262600b7d14dce0a100e870e042836ce421fcf8b8b89e01a/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string81 = /22ad7d6222dbeb747db8b41dedb9c96ffe566e86e7cd4d5570ea010904d7b7c6/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string82 = /22cf3e75a11ac9d8b492e3c97ed730957372cca18f8d5e57f40d6357de006b35/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string83 = /23fefd6e0803cb90fd71ab9011715c20916a5cddea1b07baac74a92e64106313/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string84 = /260e25a0cbe80d9ff05a9b1383bd0ac4f0d0fe0585c744ef1dc6c0e2dea45e06/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string85 = /26cadd85587b74a8eaa26e6eae7724b60fc49b5ec448c41648168748404c4d13/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string86 = /272873c13925ec870472484b99455d3e9dcbf82481b714a9fc05a7c1933137f2/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string87 = /2a349ec0870eaf921a1925be43539fb43de54a468bf0450965ce2170e8bc8afb/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string88 = /2bbe8dacf7d9ce6812dc88c629ef572ea7b7c507b240cfe299c2991a10fefbdf/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string89 = /3070edf334a7ecaf3259b124641526d1b9f56a4c67ff892e0948913cd57ffff2/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string90 = /32aa4a7dcec317cef0a8e65e25a63c0c8e656745f72c49734ca7aedc8ec9a264/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string91 = /332436f5e6ee1c744ab5c658cc360e3d9f084e39ba583d8b2bcbf2e36f68a7fb/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string92 = /34286d2404219856835c624def995c2c71413456d9a9e7b8cb5affe8597f7dec/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string93 = /3448383224c7ac46a72a5717633490909333d1a50a29dbfc4434ff90e16d6b33/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string94 = /356dd15f05b37e62f334000101f95094b81c0c473cba0e8c033bec5f9f2b84eb/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string95 = /36e59507a58d54c025b62c0ef2699382e6ca9211062540ee263544bf54854768/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string96 = /3a0743b046340770a16cdddacc4bfef4e2f07e0062669d07589f0d62af1a2702/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string97 = /3a3788e15d2cde3cc0b07bcae1b38a52f756e004cc7426bb45d275d28b7989da/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string98 = /3a828c63459e09fa4b7fd6020d9e35df05d7e03ad9214f6a321f6788089c6a1f/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string99 = /3c10eb3a8cb98f387491c7e8e28c1e7a0e885c74139c9df60043a9ad6d9593fe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string100 = /3dcf212a13eccca01b047a9becb99480bfbb9d0ad9b095407ca9b3546c429274/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string101 = /3e3a7b98aa6f420061710d64c9bda2aac9040304d2952f46661696d16aed402f/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string102 = /3ea27a3727d42fba0e3862628a13fe6458bae277d5f477d1fce626e90e12e569/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string103 = /3f34a1d2be46289a7f93e67e605d1d3b45001e2d14d78407da986f3d6d0a7075/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string104 = /400e477ebf627aa5ba9c11ef2cf9cb2bd4acc53a6beca20148f141f6f3c504da/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string105 = /41b357d80dd91685737274a7c03aaabf90d9d67245f84fd1af5eff5dc56fa330/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string106 = /41d31ce4d0e4133c1121a02d2d7121bff87c1a8ebc560181517bc72bde3e8fe5/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string107 = /4371963ea620ef5dd65176c19997b8067d5d7f72dd722a63f982b5de6659d45c/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string108 = /43fc6c375a8f2e40c144d4b47c6d807dcb9aa4dc58fff62761beab1b13c62015/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string109 = /44a2461a051dde2487b73014e314cd29b2a8f5587d88b99d13a495c5071923b8/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string110 = /453388653c7d68a5478c82f71496229ec9f9fbafbff2ffc4a3817f392d23fcdd/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string111 = /4570d2de6fa24427fe99f395693a798d918c58a67fe5be87317e58548605f27d/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string112 = /4988a9006fef04ca8ccba9ea08e63a8e960863a4106179c65d445cd71c3ea48a/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string113 = /4bd934b1beb4ce52cad55ccdbb7528fe449e372125352f2ca4b6ce4cc7f489d6/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string114 = /4c67141acad76f0a686c78d5723be5d395b51ac6f323e2ca8788f4678c9df1aa/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string115 = /4ceb965f166bdf4d8d16d081d24ad0488cbd67c955d9817b0832a0b70e38db3f/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string116 = /4dbcad57d73bd7245c37f330719add5e842b4c8dd7830039ce50ca2d615ffe16/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string117 = /4e278396d6ca4d2eb560f7cac6c7aebc0d729ffa3af3423668b5f30275aa2b51/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string118 = /4e2acdb55e74ee0525f6614436674560388b36b8316552fdae32b44398e56ef2/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string119 = /4f29beec80237718a80f87d4afc2a8d79dd8e5b680b2490653a3cacc9856be83/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string120 = /508e9b2199a8c36668fe48520c2d2ba6ee30db5fca04c7ca3e7cd42e5ce20097/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string121 = /50dae26eefa5516f7a4a02832fa065d971ca9feebbee519f2a2ab1bcb3dedd12/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string122 = /5170878a45097dd423d7ab4ec48724b4ef046ea5d990e763d18eee67af881e74/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string123 = /53ea72dc5887ad00512cccb7991fd7e7a3116390d87ddb45af322f50fee469a7/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string124 = /5469da4765d2a07fa3cb198ee9d2332862a9b270af4960e22d149cafd8f97c3f/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string125 = /54ba4f0b5b5211e027f2e97eca9b534a7e937b23e50f8db93ed573b2a3db9670/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string126 = /565bb9fd10eabae3f557cd29ee48b29054f98aa3934c2c3c2a6e6e528d06b5fb/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string127 = /56c68e08402096d11585592005d9eae985cf0d248e2f8103da15ad351eafae58/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string128 = /56ca2194c2c1dae9900e4d9e5def115af7c7f6376fffeaaef08e00ed95b81934/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string129 = /56ccaa3297c8004543544b5d56c801a9c7ac1e40bc8b9e7258634ef4dc95a44b/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string130 = /575fa9f32f88855c0e945bc076061933bbd0991f640b12da69e3a209b307decb/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string131 = /57d460230411f7d23ab6cd3463c737c657c0225df3a1aac75e049ca9d66f5763/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string132 = /59b97a0dd632d3cb6741d58d315bab9e1407bacd3c5129554cc3a61770ece321/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string133 = /5a57e519ca408107e53cc361cc237e3e57929721bc3eabebc5ab5b1275adca6d/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string134 = /5aa6d23a262a238dbddddf45fa06d182673142a416002dc70e4c893f9aee723f/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string135 = /5c0c101aa1f0e6a4ed5a67831b13a88ed9c678aaa8c2860dcdc191a8a073c153/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string136 = /5d1cf73d662aa8ef604855576ba9fa9cec217c18b4afa0794ab659b386112030/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string137 = /5e793d7d56ba10e446a23ee4523ade87336e1eff95cdded4312800bf3997e548/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string138 = /5e99f3186a99ec653ec3dcc9d6b4e3b1cfd5993ee0a33692bdf571e3e54309a2/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string139 = /5f9ea43593ac996fc08651431bfbce6408c6dabd0ea01881c56ef6d083e8b0bc/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string140 = /5fd16aba9217f23c9bf91eb92f870f9b368f2a0da3b2799a88ac63454f2a0559/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string141 = /662aa3c30a3486158b79373f1ab537139a069778519e8e42455e846ff4bab1f8/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string142 = /693475b69741d88b18afca69ab81daa69d5b7fe8f5f6849f69676b62c3379af5/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string143 = /6a43c893da2a0f2fa6dcbec833f34290385c9ec44f06a358fadaad4677c9ae76/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string144 = /6d2e71d3158ce74d7cd53b333edc7389b02c9d473658b87d898a7a40e377850c/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string145 = /6db1c295c1602011ddba8c5d3e43d8c73f247d1367fa2600062862004b1e88db/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string146 = /6e469301d72958686bc78469c7c9d6a79fb848e77e6b00a037526d44f5d48819/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string147 = /6e8947870ecf553ed99f745eb8c66fd7daf3d60fb16f5ff44285c7c7f11137c0/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string148 = /6ef99a03b1df823546e414b4b3ce5ce0e43121db66b52c9e10b61ab653b46bf8/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string149 = /6fa10205d1ade554f1f0250db2752f855919abba4cf63efb907a7543efc1beae/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string150 = /6ff59cb7898fc8534f0a799029d8cf5b9b033c1d19cba81a91b6cb05415d34c1/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string151 = /778dc2b522e8c8a828ac6de8c286f136bfff01ab570d90edc107ca21d68bfde2/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string152 = /79571f764640046994297e5c3123fc3c5243d5df378a16abbce7abc30ebec829/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string153 = /796c8853196cd8a5b4aaed85718ff95c86006200fa5f579a9523f66421873004/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string154 = /796d3702d3376d0116192eef85fbb05e2f10531c57958489bbadb92372c120e6/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string155 = /7983d5af3fb00770345c09aca16a8d8ff122dbe81b58a0de69b571b55f4dae1e/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string156 = /79f5c26bdac4bbebe20fad039b028776f064003690b4141e9db5fd01c3262901/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string157 = /7b430460f7b6eee413a53e58f7ca7ff5c5f66c9e31fce4b2f02c9fe76f251301/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string158 = /7c4914fb0be3e091e4c693c4c6c31824b75b270a97ead524a4795b6d32b6b6ce/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string159 = /7c8a8e35b0104fe2fef94a7c7cff468bf7447b77b1018fc1d692da9d001fe3e4/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string160 = /7df5411490635c5c29704e2fec13133a27a4acaa35255cd22da16dda1b9f5f24/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string161 = /7e735d5682bcc025c49cd916f004ae6649d736bae2e486098cd34c29e50c21cf/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string162 = /7f0125964d3060da6c75a5229f87c9be434abf3566c2fcd3c461868aa33199be/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string163 = /7f59d8d46332b5cd74fa92390567375011b6123e8ccc2a1b4f91fa17761cd617/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string164 = /80fe638eebe79635247d036438363f307f96dc388ca50ac5d4456b121c40b702/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string165 = /81265cdf4e2efcc4c9285c8d2a4cf2716f0108d861bbababd01cf4bce9b2486c/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string166 = /820b29ceaeed51da52cd45987f9a0ebcca4335aff654204393c0705e83324d50/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string167 = /820d907e4d5c567988b402ab0e31414937fd187b273004a538880f20aaefaa21/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string168 = /84b735e9c0af06be82353d3cfc511ffe8edcfc7e2952aceaec7221b282488d69/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string169 = /87c0e2e1aa8e9c492a4ae12219f7a14cae0724c57a127445f92513e4acc962b3/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string170 = /88489815bf08cd6b93b92f3c21c76926e08c1c4f3e31c2f4a303eaa3b58f6c91/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string171 = /8988af63d7f1d5a9f1ffaf6f24c487e8713df21faf0ae8fc7bfb7996583c02ad/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string172 = /89dd76ded9f76dc5e8590241d0564c26146f3716d814a5281d65a719d5dd66cf/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string173 = /8a2ee3773f2b5a22f6f01569e9d17cd3e1eba7c2e215e043c014b4bc609e55ef/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string174 = /8b0da574d5be1c375f60b1f2e93a77ba8a1742df128a8557963757434e2375e2/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string175 = /8b4025c1613827180ca686411119d98da4b7540017dfee4ec0daf6631b0394fb/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string176 = /8bc84212c03f5e2ebce1c44cc5e1315309cc685592023892841cf0873a2b3560/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string177 = /8c55fb2a90cd6c8f90e19b1cf4413ba4fc427a67ea6cdae2369abf10d3a83e88/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string178 = /8d94ccdfe844f9763d5a09b3cdaa68b44916b16f6ebcf92481837860ad010c82/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string179 = /8dcd8560184c700cf3800cbfa76639d1e3eeda602963c40f56390626c51f9aa6/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string180 = /8e306bcd87bb1fbfe39a22da9ab02751cd9289b721da818a7b0cbc2916e98493/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string181 = /8e7cd66e174744da7d7c8ec0d9caee4a0b1a57d9f51d9967ae1e8fc78f938a82/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string182 = /8ee8ca3b67ad7256a43c6a7d00cee2c22ff45929cd69d75e7212c42485f37c97/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string183 = /8f614310b7de7c1d7e19932a82f40a91e7c328966f9b3dec08fe8266bbcfdc7d/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string184 = /906c39d77d4fab235031fb83f0dc40657c4c25251be92de4236551c15033e997/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string185 = /908fe7bf70340eb71df77a54c9fbcedf514573e81f6efd15a9110b4a25d9b878/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string186 = /9292fadcd27e41de30c6cd2356f882a53488ff91f60999170dfd4be311af37fb/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string187 = /92c129a8547733e8de54b84e7e0a233cdd1330083a07cb1309926eb8dd678db9/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string188 = /930fd8e9878e8e96b022a9ab62f3471938c8c93898914df46a02d49f246abb22/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string189 = /93502803691a7c14ccd0c0132ac8b12dafb621e7840243887150c3e68836b998/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string190 = /954e01f392b21020cb6cb21c13199d8768ee00e24ebf32566bfdad3a212036bd/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string191 = /983582e34fcec444e33dafa6b533ba974086c16520631cd2f07fef6f523a8efc/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string192 = /987f7e9147612ea1182fe989fd19c70cead695da16ee63dd26458ebb43c7b556/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string193 = /997e2ae3d49570976fdf7c1e743d23e619f8d8f3fd6fcc689545e5c357ec95a6/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string194 = /9b6df8785bfcc71ad646fd17f581744eff6993490e5cfc1505850117eee701ab/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string195 = /9bde1bf43cd8dc8d67f5e2b773d4315344315b4a52d2be26dd49c484678bdaaa/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string196 = /9c61fb474707f74a2bd8529b5ee56a26baf315458c07cc8aff66d117081f1aea/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string197 = /9c78d685436d461ec75c3bdfcd09503eb86ce64ac58c13da6a8c82bdc2e80703/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string198 = /9d4c213bbc51347764c8b62223c50da024037f63150d7f57ec12e22d1eaf0dfc/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string199 = /9dea73ffa9687042001217d5dd36ce8083f36849cadfd88945cd55f669e9bb70/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string200 = /9f1af621fb39dac8f826f5c5dd50cc8ef3539be72ae9b06a5607eadc23d4dc0a/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string201 = /a028984075f63af783a3a261c58350a9d153e63c277db78614fb4b3aca780631/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string202 = /a0e7d15b84357f97ac46b469e179a9932682d5763204ea90590ea71ac90aa515/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string203 = /a1cb3625445b64b0302323e1f751ae23885d31e5a260766f85f492498cc43362/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string204 = /a42f8bc0fa9c489ea06896d74810c9bfab10738b137bc567c3e656ec6f8f5d1d/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string205 = /a46a1cfc06ed9eb2276a879dcc949fe0256d511cf0925ab2343b9e92542fb8f2/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string206 = /a67a2d20c217e9923d9a614870d54152379c8d4f2232114a158d5e88f9ccd4b1/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string207 = /a6c8218887fdb66cefdced3195f1424a714add1f6fe369ba7ddbfe1e7434191b/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string208 = /a7266ba33c7873fcacfaa675551204bbc56549ec7d859635822009e0e2bda9d3/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string209 = /a73a39cce96e40c9e574607561cabeb8f0b46ffa5b996c1071d434e6a72e34bf/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string210 = /a7dff33a69fd314049f9b1ad78340c875ba5681eb4a828d1cebc79e6f09bf35c/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string211 = /ab775568ac52bb1e4ceffa6ae38c7bc11d769a6ee52cf964d9ece909c5a397fe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string212 = /ab8b178678ce6ccbfeab5183c65c4de04eb768892f5710557c297e45cd567dfe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string213 = /ac3d4ecb448c66634efad135d94657a27eed4f8c30aa7f32e4ecb2da621c3d47/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string214 = /add859c23de8190eca95058cc1cca930786b1c673b8dd3e25dedd8e12396469a/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string215 = /ae494aa39434950473ecd7ba70bd89cb9d10cabbe7637b9775a4ba1f26dee665/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string216 = /aebfc8f6a11074dfc2e95800f32edc984abeb67eb6a07c2056acb149fbc37e66/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string217 = /afe5cdae79e5f79047b9fbca32463a6b5b82b9f0b11c9ec712eff47f526a5fec/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string218 = /api\.remot3\.it/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string219 = /api01\.remot3\.it/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string220 = /B00004294C7ABEDC67BD41B0F3CB0C9730BEDA03BC3CE2709B7F838585133B2C/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string221 = /b122583cf21343bfe83444d90b3223ff4abd42738e5817a1ba5095ddbc0202ed/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string222 = /b25e38016ee6cae1175968f4686699588b208d14f27320052e097c5a252d2d1a/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string223 = /b38a8c339aa39c37a3680e31876bc6b4e5c9f337d4c0f409fd17b696befecf93/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string224 = /b50382b91253028e0f21ca8d585456adbdd8eb05d20efe8eb024ff2253f49a3a/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string225 = /b57f1898dda9bdacec25669b4a8ccdb6905b5d0b9c9d0c4c3695d8aa54181bee/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string226 = /b582450f8aea64cf41134d657ff610825080ddb317b7cbc1f1c1f1e4dd2c1978/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string227 = /b64d241702d0970bca644bf2d2f90155cf12f0265cd43377e58e5bb4f54c487f/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string228 = /b70a71c6d30d106c21cdfcd3d7bf61f8eff05d28d22538c6ea335e9818999cb5/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string229 = /b754705e934ef0766078f0371a1e83007dc7c85ef02ccd72da4571736df1914a/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string230 = /bb016f6b3e240b6447a72b15b103d32b8239969ac4493b8522b4f22b21f9440c/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string231 = /bb136a7de55ce17c6a4fd59319a724f80e53a89d0896675cdd78f98cc7bc7858/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string232 = /bce4fa4709599a20156a3ee315899a479e28eead968db5af6199bffc7288d256/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string233 = /bd07ae00c8a28ce61d06fb344b8d646696ac3a9eba79b0df1612736009b7c509/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string234 = /bd313c0a5313c056ecaabdb990ed5077602f6e97e0c57b2e21a643b06d211eb8/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string235 = /bd6f80e0290c96f73f6cb4837e0050dd4f66c71cdca9da9afde6a619b4c09f11/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string236 = /be4d5112b9928f8c5dbb51c2e67163fb82fed8abdda5b75ffafeff43b96fc8c0/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string237 = /bf33607b1f28707326ad3cda5bdd5d729e28b7c826db8c7c2affa68adf5f50b5/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string238 = /bf8b63373a944d43c2c3c9b4c768cbff723526d25f40e5548e47318c7ec1b674/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string239 = /c13136af014ba278cfd9f3a3ba1d9fd4e1996c72d32c068c3b259a8c5930e1d8/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string240 = /c1b657c2bb9c1713b0a4a6b5eea12df8b16dc1e82d1655215573575bf5a710d3/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string241 = /c1b73bfeb5933efe372525bb800f452e335247cec34ef4ca214069cf83928e45/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string242 = /c269975b163143664260be837652e7163d150453b35f1d97abeadb31c9e47d66/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string243 = /c3bdcbd3ee63b0ff732b9027161d0e75550783a2285f36ae0b3940886f3fc1d7/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string244 = /c477182f8337d9b0ceb73fa2de3f0384a7781caa47bf33845ea7552746e6df65/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string245 = /c4b51b5bdd584b2901180946bd0325d1673110a9f6f2050f522404a280bc2d3b/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string246 = /c4c77cda828b390796df90293a7595b030a9966af3804451295766b2d6d57a31/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string247 = /c5baab0546d6a6f34ef0b571c8d16df52e8ea3093515986ae3eee3755683546a/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string248 = /c5d0c469b322039c20ffdbbc052083c342a0c1b9b2b16b47be469e0da76fb3f1/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string249 = /c8a0f709cf4759d81ced139804cd7f790590fea22b34e00a7abe57431fb8525c/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string250 = /c9192193554c131a5f3c8dcdc1764bae1705583f853f302d48185128fdf7594c/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string251 = /c9cc2b7d5ff7a0f9f7b97da9bf4a090bfd323be51bda6c12eb2b01c9efa816b5/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string252 = /c9f5f2d7fae73dc38b27872ccb37559f5a7dd96b15b48c6e54bd6a5640d852e2/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string253 = /ca8a4d90295fa5049d85ac5b867861ec4740f64f5f3061a1c0308d2a041dbf2b/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string254 = /ca9099738d41c98fa1f8fe983cbc9071e37af846c851311316ee8b38c2cb5706/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string255 = /cb923918ef4e035f3ac3c144792f3d20e5519741c4e1f56ff9bee53f6cd4592c/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string256 = /cc5604a463e90dd1da595a73e2fd9e0282a465fe7cd41f46e34ed05a7b84b295/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string257 = /cd386a8883d2da370ccf24b6b29313bd58510ab87bce674ede931eb1310b153f/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string258 = /ce9bd575dccf2e5b373d8f7b1aca7cfdbf6d9a4e9179a24ac6d92914b3f782d4/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string259 = /connectd\/usr\/bin\/connectd_d2d/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string260 = /d0a44c5acf4946e913a8534d362d681bd50205d00549d3db028d8ce2802e9b86/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string261 = /d11fdf3e02243a642c2158357522d457d4111058723c5ce79c355c40b4495350/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string262 = /d1455ccf2efda304183873600535c73e8205663b384ec30a8c9f2e6ecd0a91b0/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string263 = /d1905784a1ef416d990ea8cbe68e0af88e2d33a4b2a8b5f9a75e056405a7dcb5/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string264 = /d34833e0daa78c9a9a36b3ff311596ec7d010afa18d95ca02fc6ee577630d81a/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string265 = /d3f7f5fce71cbd20a86771949c9fe143cf4732f69db1cd9beaafd6a6a9de795b/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string266 = /d57bf75bc694c0f583e9e23acee5dc35a2ab719a842adb52008ed494d0cd5979/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string267 = /d6e5f1a398a35682f888bbce3b6187389d845778327479fb80091cd7ffcf78c7/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string268 = /d810084b9bb4b7c552be24f744165d6a46d777d39bf36f3a5951df7108b77437/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string269 = /d8289c3873b04fe89664452f40f859431572e3417ef3fc102d7eacf8f8b288cf/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string270 = /d9d826b12867990006f7a5bc6f015d0effde87b65427c0a3f7b23370314ad16f/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string271 = /daabc151e0d5a6436c71bceedf79759369a11edb7fc75a2dd9b2f32098ac2b65/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string272 = /dab18572b7ed5e6c70ae7e1973a6af974aed0ab30bed7d385a92ae7cc22851ac/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string273 = /db8f43c3b82fa1517800e8672750708886820c4eafe4d72f96773898ad996588/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string274 = /db9fe305a4ca18b39e80a2b5bf0f6ea32bf41b968798897703647bbeb39e11f7/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string275 = /dbe984e84ff23af911cf29adb0c3f9fe665f873708b5937a44b156846029a43f/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string276 = /dbf767a606cbb7c653296843204fe570a8b59b622faa3315ecf555ecc6e0803f/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string277 = /dc42d5e6752383656c1cc05459bd10dd9f6a25c3c715a38d1c14dc0391a00982/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string278 = /de4038e39b557638be260ddeb85bf3e6e806aef81ac07b681b0303414baf99bd/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string279 = /deda21817db09e3239b1cd5be4b8bfdeb8a603a285b72169927c246970b99b00/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string280 = /device\.remote\.it/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string281 = /downloads\.remote\.it\/remoteit\/install_agent\.sh/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string282 = /e1ff5a314c147e1e6d7e7ae3d302cc0b1734a4e8aa20d35d2c3e786b1438e164/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string283 = /e2a5be5bc8d923fb310f98b974e5dcfe0c308dedd9efe931923793ad7bdace9e/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string284 = /e2cbbea92145e924cec43ae92bbb865aa3b31e5323af273724ab2a56cf01e972/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string285 = /e4b62f88bc61b3a1ef4cc83ba6aebefefec75ab246d83e8708c3cf1c8c3240b4/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string286 = /e4c382716cdf1d4d582eb2ac3279f498c8e335d119737fa390a766296738ee87/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string287 = /e7b060f41a2322c481867f623ee711a321d6fb554fe816251f1381d1669a68c8/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string288 = /e7f39694ec1f97181d17f0f9b8fbad820c5bc98289602f7a960916142596c4b3/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string289 = /e9cbf615487a666b2fe9c5b7c749fa91d4af0454bd368f4f3275148609f553bf/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string290 = /ea178a3f4a3bf35c1998533cac58f1bf5fb90ddca42540d29d8efc1e93480bb9/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string291 = /eb60b71cf30ee2975270b48a31c4e2d1812e61bbfb4f5c3bd512b578782e7b3f/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string292 = /ebae9cb602d9475764d0abb184a85747dc86c0a2c683357f9bfafbadce743030/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string293 = /ec3af0d72abfdc79b417640ec6d170e079f6ebf4917f0a317aa441a64851d85c/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string294 = /ee0917c3db2e6a92e681f9b3b7837165924df74e5ca5bb9c3f7de7f411c9512b/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string295 = /eee0125ce7d147791c5b6df258e849476727218f04d1ebbd1a305e64b8e9e777/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string296 = /f062d1f8866ffa374149c6c672e92947654876e80faa847b5fba3eb098b22d46/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string297 = /f1f11c0e9dc81dbb5d52bfd190ad7487c124c20c248ee224d8163ec9d703a096/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string298 = /f309dc9fddef92be50048234dab7ef0fbb0af6aae0567ae60459a8a35e8d36f6/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string299 = /f410d7494e1e07669dcd4bb02b08f5b79720f7b11522e7dac064d2336800fb00/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string300 = /f48343180d92f8780323d45addd6ddfae8d496fa31b1c9abebd8e543db544443/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string301 = /f4c231ebe0140f82fe4b1528171c9fe0cb754ed803729681e2187adc68d9accb/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string302 = /f52084516dff0a54b9cb0d8c8ab961db1154ceb43261257e7ea4e57cef4c1991/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string303 = /f53253575b70dfd206586899b6de357f5288ddfae0e4bbc54f7804f01719cb76/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string304 = /f5e53a8f6aa666cbbe9c0a0bebd9e0f1315e7e9f9348cb4a341602c14b2943f9/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string305 = /f6363909101b64b4aeea40fcd365e4d71e70a5f01bf980670309a5650bbd9254/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string306 = /f6b7b1c1dcdd6609fdee89557038818bae31850094b18614529e080383b8c5f4/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string307 = /f84ef28bd00757a3e609bddd4e1267d8d0adbc25d3014bf291f3924139900c65/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string308 = /f8d92121ac270672a940549d33b12b35414ddc844de5a56874b567bccd607b94/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string309 = /f8fab0f7fdafeea49e8d33a69185144d1116fe95ec89ce8b0ae7ad7cab21c70e/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string310 = /f905a60a79e8e34f9a747703c5a34aacd35ef8fe07cef2dd4caf2f2f332f419e/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string311 = /f9f02edbb1ce8805f22db9c97cf582d93bffe67fd4fbdddd67ebef132a8f46e8/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string312 = /fb5f40bd41ffd98ff11efcc9afe2f431699c372b8806df096d7270cd5eae06a5/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string313 = /fc80434203f482e80c4dd8f509a5ad4dae149a62399366b45b285ba4577e7cb7/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string314 = /fcb77da2f09a0fef3c5c97c9aeec535a92977beab31fe315cdc5fd855f964fcd/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string315 = /fde10089445a9891714b268d69ec4de5b5457ed084fe091cdadb23c9b432c271/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string316 = /fefb2b5bc41354345598c2f69090bf16f7f1add348fa6a4bad60dd8fb0e73d40/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string317 = /https\:\/\/link\.remote\.it\/support\/rpi\-linux\-quick\-install/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string318 = /Please\swait\swhile\swe\sstop\sthe\sRemote\.It\ssystem\sservice/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string319 = /Program\sFiles\\remoteit\-bin/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string320 = /remot3\.it\,\sInc/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string321 = /remote\.it\.developertoolsHW9iHnd/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string322 = /remoteit\/installer/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string323 = /remoteit\/remoteit\-agent/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string324 = /remoteit\-amd64\-installer\.deb/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/desktop
        $string325 = /remoteit\-installer\.exe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string326 = /systemctl\senable\sconnectd/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string327 = /systemctl\sstart\sconnectd_schannel/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/remoteit/installer
        $string328 = /systemctl\sstop\sconnectd_schannel/ nocase ascii wide

    condition:
        any of them
}
