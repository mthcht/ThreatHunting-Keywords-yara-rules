rule File_Tunnel
{
    meta:
        description = "Detection patterns for the tool 'File-Tunnel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "File-Tunnel"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string1 = /\s\-\-read\s.{0,1000}\\\\.{0,1000}\s\-\-tcp\-connect\s127\.0\.0\.1\:.{0,1000}\s\-\-write\s/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string2 = /\s\-\-tcp\-listen\s127\.0\.0\.1\:.{0,1000}\s\-\-write\s.{0,1000}\s\-\-read\s/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string3 = /\/File\-Tunnel\.git/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string4 = /\/ft\-linux\-x64\s/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string5 = /\\File\-Tunnel\-main/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string6 = /\\File\-Tunnel\-master/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string7 = /\\ft\.dll/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string8 = /\\ft\.exe\s\-\-/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string9 = /\\ft\.exe\"\s\-\-/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string10 = /\\ft\.exe\"\s\/install/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string11 = /\\ft\.exe\"\s\/load/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string12 = /\\ft\.exe\"\s\-install/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string13 = /\\temp\\ft\.exe/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string14 = /21f131f283dffa84c44aa6c4c62bb97b77c8de8a08fb6ba50a449bdf9fa8bd46/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string15 = /26ee5086d8cc0404b7088ebe9e121e090261ce9185a9d4bf2394504fc8415f45/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string16 = /2fbf10428ccc2e463e88aae2aadd3efdf686d510c42d7b5aca2b4f126bb8296f/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string17 = /35c8d88f94fff53d9dd573801f16aa02e24f771668747e3f0d2975ff4d0b85b8/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string18 = /3aff2f105c353378acd29dc43635769952d715d50e8cc87df39acf938c06d7c6/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string19 = /461F72D2\-6BDC\-4D0E\-82EE\-59A811AB4844/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string20 = /527e1f97594b67b082c6d687fb93e15c1409bbfcf6584aa019260a27af027262/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string21 = /54c3dcecfeb6224d49ae655207cfe684f95480f16215e32a122e473ac275d0db/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string22 = /5eb4a246d7a9adaffedd89bcca6d86ba57a30380ce90438b57a45e61b9e06ec0/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string23 = /6938eff2dc2ec73ed1fa0c5b70827ecf2ea031a8486eda7f7f72ad3da4576b25/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string24 = /70f60b2e7f6e64317222ec504392f975e14fa9cad5ed05329f6eb8d7bcff6956/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string25 = /7798bda9fc4f194ab8e0d876a27326abe016f35eddd6799696670c45888475c0/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string26 = /7d057f377006dfa3f88af8ef1f3d90a9e28d7ce83c5854988865c7fbd62963d0/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string27 = /8af3e901ab7c19e8ad6f8d8caab23bb8ef1c9577aa4a5c5e4b43309306c4a11a/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string28 = /8b440c386b62c525e2dfb90008c3070f481747a5b6929a4f31878429d6f34c67/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string29 = /8b46156114d2138894c4ab91a8d5e4509ab9c559cef6c349ba45f631d4b4245c/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string30 = /8bc3ebd6ec1b70d73eaa0b1c17ce124b4bd3fbf9d7c1de6f1f4c11e9da92eabc/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string31 = /8e412bd460d0481671cf9dfe4ef2d5521f3a658e8c3ef1deefa7c445629ee667/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string32 = /90e8f7a8ab2ad07168666a368e3c9e3b1c8c0fc44257d693b76694959e7a1fb5/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string33 = /92e355ef8f0242891884e4bc51d2422852fdb08430c36a7a9f8f384bfaf975d9/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string34 = /9413f823738aee4917952e60bfeccae88c8d103829a9831f912aa87c6535577c/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string35 = /990953dcf64c26cb505d9c19202b849c7f7131209cba13665e91ef500fc266eb/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string36 = /a19ddb663db4b66ea06b8cf9dae66f6988e0a70c07cf9159e1c6abc01c415f95/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string37 = /a5db22a3b93fb89ea64a3027801002e968ab7d11e43b2c8e5173b33ac8fbb8eb/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string38 = /aa64f8d9cbcb6860541a56e17a6ca22371553ff32e01d218718b2155e7b8e475/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string39 = /B2B4238B\-1055\-4679\-B7D5\-7CCE2397098E/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string40 = /b4dc2fcd506a9878c5fb8e8b08a47c1e810eb48465a6b489bc4b5003711b0522/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string41 = /b7f57aedc361258fea85dedd3713454983c561335cd9d2d8d9d072a0e7ac8c7d/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string42 = /bfb894897287d8652d9aca74ece09adb061de853ed9b7707c1f72533cd22598f/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string43 = /c59d5571282b31757c89952001ed062772d696e1df2f036b1d4328f9eb99806a/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string44 = /ce8a96ade87a39ebb8e4dc1602ab2b80cef1fffc317b557c258839223c65667c/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string45 = /cf2e73e6453dad578e2fbc308e7dfc4d44fc2eb93e612d466705723fe858f5d6/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string46 = /cf615f0091a045903318a5c1d3c7eb37d337c26ceb3b682a3b68fc820913bac6/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string47 = /d37c8c47e154d9b2021eb2c857a2ed617ddfc4aa6e644d2302bca09a18d06946/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string48 = /d4dedef47f4a8c940f6455c170ac17778e558a888167e64ebc15ae44b27b90da/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string49 = /d73fc7fcd3b0983b7ecc9590562fb0e83611dd1e3199437b108a69cddce0ac07/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string50 = /d80344fd9c189a4333409958250a0e3ec44a0168e70f5b6b8c78588c8ed3caf4/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string51 = /d914afd1408ddbf0aa5180434bb1713748af7d4936724b392a0a2e0307ed9dab/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string52 = /dfce96a8631d54b7db3f4c222417d94fa131b7704c32cd431cdf6e04a945c1b2/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string53 = /e91f4e67f48ea790700ec6c55be53c6d2ceb6dd091de3de5074d559cfdfdf02e/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string54 = /eb901b02b7f7173e62a962b9d5d66b52ed9b47fcb8061165a1b2bcf2a5e5504d/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string55 = /ebfb867fcb1efed0a7e4d9bb43b5b6d22f8744446bb29bcaf76aa6a48f36bf9c/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string56 = /ee604522baa122ca8384531d4d8df1014023d871f1d2fc4b53de17cc6d5d4acf/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string57 = /f632fb93b89b788f346784f9e18976a2a116bfd67bfd740feb5dc61c06141e29/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string58 = /fdd96ea14514b4f377414ec9bec2ba356e0d4ea8f019ed34a9764f960884b386/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string59 = /ffcce186e5ba227e45785a92225b8455b29da5b85d0b030c0346923625d495dd/ nocase ascii wide
        // Description: Tunnel TCP connections through a file
        // Reference: https://github.com/fiddyschmitt/File-Tunnel
        $string60 = /fiddyschmitt\/File\-Tunnel/ nocase ascii wide

    condition:
        any of them
}
