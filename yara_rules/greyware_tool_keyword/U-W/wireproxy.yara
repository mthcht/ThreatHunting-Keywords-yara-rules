rule wireproxy
{
    meta:
        description = "Detection patterns for the tool 'wireproxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wireproxy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string1 = /\swireproxy\.service/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string2 = /\/bin\/wireproxy/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string3 = /\/wireproxy\.conf/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string4 = /\/wireproxy\.git/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string5 = /\/wireproxy\.service/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string6 = /\/wireproxy\/releases\// nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string7 = /\/wireproxy_darwin/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string8 = /\/wireproxy_linux_/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string9 = /\/wireproxy_windows/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string10 = /\/wireproxy\-ci\-test/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string11 = /\/wireproxy\-master/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string12 = /\/wireproxy\-udp/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string13 = /\\wireguard\.go/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string14 = /\\wireproxy\.service/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string15 = /\\wireproxy\\/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string16 = /\\wireproxy\-ci\-test/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string17 = /\\wireproxy\-master/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string18 = /\\wireproxy\-udp/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string19 = /009878ba04d0708fd86cc333fcda1e4d9f6a908b95bf28484dcae293bd497201/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string20 = /01553e1a8ac9b5a158f2ff4861643892ac018aefe598c80fb09710c702b70d8c/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string21 = /01afaf85adb57c17d2d817c34134ffc1804db080b9493cc7e1a45e3288bf7536/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string22 = /02b26e392e2c9043de39d0c39595b587383170b211b2b86f3499227100192e41/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string23 = /03e55f4304347ccf6363e5770ac810b3eab5212f734dd9bfc6835eb9423b24d5/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string24 = /07311a98f0eb27945a68e1013e666e2ceff69c9241398b7d572086baabb145ee/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string25 = /0b8f89e4fc750945542db27755503efb9f7bc315991393be3841a5946cc1f1c9/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string26 = /1770fedc0630c7c0602f9adaa1ef853a44cd8a889bfd0786b7cdc8aa05f61db6/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string27 = /1bcdf25876c01658756741f64fe06654583e539aa3139bdf55ef1324137e148e/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string28 = /1befd6f9e0bec802dc6a4e2a33a85c967bbe3eb6126c1c4d0182f55aba1166a6/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string29 = /1d023cdd6aa17ec552878b1d36e3ce4fb32dc5b9563042a35452b0800c9da124/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string30 = /2146c1335034e53171750fd914adf88e77bb5d9b2a98c61632474a97ae5b016f/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string31 = /26e454248321c9543371ce81407a9eba31ebe35c58667daaa588965cdee501fe/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string32 = /2dfa8caa50560a707a4877e2c9bb40acecaa475d5b792ef78f5309a46038f1ba/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string33 = /2f4e89575f662c72f7c1dcb4f7b5d2bfb356594883e39b0d3b6e17dd941c278f/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string34 = /319aa6516c8bef2fc13ae80390fb4a2a99b8ceaaf6ceb462842001b89f22bca1/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string35 = /31c085fa529ca13e77e2ad911bf901a0d0c7e21cd27142b09371da30d676ad60/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string36 = /3204a42f02f8cfed9ba183a2141e16079ad99854b74f9a9e0c6a4831e8b25d8e/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string37 = /340318e256a321e87e1a56c948c1d6ab6dcae8f585aacb26b0de457b215b9fbe/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string38 = /356eae02a0b678a82174417da439cbdcab3e678197aa8a91824849fb9085fc32/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string39 = /3e6945f3127371b2f2c3f0bdcb2a1c574f92394cc78fbe2144ecefe23f83c983/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string40 = /3ee17b78ee6df429959331d016e7a2a64931584c70275c2b72da8b5ff33a3d59/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string41 = /4019e9601d40a27634c95f10d98a0ee8c6820d2653665d8c718e132e92887814/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string42 = /40eb2e3dcca0c9f4ed11b3fd96b5824489f60fc0c3caa8f609539dd68ec6f1d5/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string43 = /42f742e6fa63b5b289083c4d17d57065e599754618d56d6a4690199436cdd316/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string44 = /45348fbbfaebb3eeee47d5a96c4254e02e44da4628427fd5da1e5904479b5ce5/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string45 = /47b8e0993b997e7f465802945187521ba8c68592af990215cdf43bef121f8df7/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string46 = /47e0483c22d1a0554dfa2b9b51895e866932b4c7269dee4ccc6ad41b3e433abc/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string47 = /485911ecec88451f4e4272a732526b5024b815630d0d238c452d7faa097f39de/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string48 = /487a53f4e4f82f5d0789f4cc7b942bd2accddcd2eb296669afbf7d8cf91c421b/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string49 = /4acadcd4e74a40bb798d207b3d25b4b5f43cfddc39f9beb78fe5badf428b47a6/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string50 = /4cd912755e503c2010ab1f436128165f1f899c384bffce49f183c0663ba5da22/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string51 = /4f3bc75be8df0f82b7b79041715ed30cf1a0e658fe2be024825da74c7a8a37c1/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string52 = /503c58501ddb578dd5ee825bdacde7e5e416210276ec7e6688c8556dfca9ae26/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string53 = /54b3370eb307a1b726f60f1c1accfb1159feb6e38d6dfda1fe1c6c1d09f79446/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string54 = /573af5ccab4dccb4c9eb1f21b5e65d18c0b3a4e2b262c426b6bebc24243904f1/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string55 = /5a1790facd6c8aea4b8c49a0e8d4aaa2f65e367a5d15c8f58014d62a8668b4df/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string56 = /5c247bb774e29eb43ef20279ae9d8cee98cd0ec4028dd282a09f0bb84f379976/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string57 = /5c4bcebb1782c9cf6c993a076f306555f62b1c8b14e149478ab2358d5a6ca517/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string58 = /5ddc8f41b610fd28ff2a50d363f3085640b3af7278103524bff3075ca2dd993d/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string59 = /5f523d5a29283d1581a3444d2bdfcab0afd70cb8e2991f1931e70f89e6d8b271/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string60 = /60e6f67d6d09c7986ee9b2683a77eb28d2004ef5c1fa45ef9b9358bca170fc16/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string61 = /642aad896feb5dad407faf2d4c863afcf715eec4f51b21768cd484867c215031/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string62 = /651574316f30fcb27c5730435566812d3bdd67c5615c56473ae2ed1e22adabe2/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string63 = /65b130644bca2559f84fca5bb2bc22a1ae7d889f01e8905f9799763720fccdb6/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string64 = /66b52ee470feb8f6d2e6bc138a82d0db8aa59511b3c9f6d44300250ed7273ebc/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string65 = /66cb20febb3ce35cfd4bd1320e7abd087c6b23aa457f6e350a8b05fddecc641f/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string66 = /6abb1bc9f730937c6bb77f096087aed70599b3e708fe645dbcf8dfe6240d005d/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string67 = /6cf85567ac67515da97ff2cfd2adea85a088c5bb4b8eb3fc847d6d3d5637b842/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string68 = /7a70080db23b2f02e3304cf2e5d41e75286e28d33b79d0cf514f0161dbe378ea/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string69 = /7ea81ae66bbcb8065d3b7d00c7f67738a4f9fc5c38a28a6cd602552369ea3343/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string70 = /80594939a5a0caa3ae0a8425bb0cc149f1ba31b4dfc15fd183ca2ff1650150ad/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string71 = /84024388bfbdb79a8d084767325ef4b8f25c6551f50a1f9beb2409e73041644f/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string72 = /851dddcb60f2e90bc02a00a056ec9bf8d131082b0d7e3b9b7bf67ac1a381d297/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string73 = /86bd9d5adf837decef7b59ae3a02134103908a249ddd0457f4a688467a42ca63/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string74 = /870089165f0603447e099ef6a27cbf0926fda8cbbe1df6fa3c7021897f1eabcc/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string75 = /87a0056914c80855f8226b2b23118ed48776bd46a56d1cee328db464ec7502a3/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string76 = /8ad37d3ba1aeb25f8997349cc4d1ee21540881ebb62249c5b4c95a2a7137dcca/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string77 = /8d9a8c8e646b26d5242d8fa7018bc58147435076d8b9c19fb3df35be786fa2da/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string78 = /8e459ac9f01ef6901b45681fe24dd1abc411a2e35a85a108f9e209d1b0182321/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string79 = /905a3126b66ae96cf8171b13f7b727d44971636c1504a496fbd1b7250a491711/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string80 = /90e0acfe005774296f6b39b88bda3819bb29f0debd6340bc048bfcca38898c8a/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string81 = /94158766003e207f843092ba29787aeb83800799fe9f605682c761d8c75deba7/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string82 = /969a0ad64c9d99f21d8e8a8201fa19b0be3a757d220e89492a4d2f532eeae126/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string83 = /98d3073aff25e6cdb287e366be5de18f461b7e820176a5211dfcf203e8ef6680/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string84 = /a35294253d487a15fd813da9ec51e1f9c71e6ba81a5e19caf2401a87572627de/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string85 = /a48e07ec7e49b7db108e6491d061d118b5c0b52dcf3bbc60390d4b2b9011f8dc/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string86 = /a6990ac66bfbbfeaef787dff39ec08610cca7c77d33747b5a76583e7f7916f2c/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string87 = /a9c55684d85a79c12aea4a9c4c43be98addd32f88c21b240979f47b8c04cca02/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string88 = /a9fd574e1f0c58461722fc1abc15cd01efb472bcdc1f703de2b918f2fa7dec64/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string89 = /aea7f25ff97c149ba56c8b4c956d4814269c6c66a5d2a215ef8333ab9499b2da/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string90 = /b03d96d8d00893f76bd9c55b7ce47750222728e30b19d23e1a39e0239ea6420d/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string91 = /b39aacc5eb127dab66d1ccbbcbee9ee6cf659d27ebe9cec63c4940754acab7da/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string92 = /b673a20bc465d0312a145da0fa9382d990b4f28d2d492452be952a32c1740f50/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string93 = /b6c43379ca375e18916fd220fb5bb4c76a0bb75c5e83532fa47d6f74aeee61d6/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string94 = /b93eda57716e1c55030ac507cbbb9c70b6cfe3d0d5b9041742b4a5e90538a90e/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string95 = /bafe621127910335db84dfc38a60088d1aaf6ab52cf2ecebab389457103137b0/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string96 = /bbe8a83b968e62d2f07b427ca70f48454a33e44250ae43fbe917caf93bc0da26/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string97 = /bc19099bd718989cf9f415548edc77044563a512dafeba5a2042626b3238df6d/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string98 = /bcf09d38544f07d19337c6c7cbf1d12a29f418d0f85cae8c3af17f37b63d5836/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string99 = /bef4bc1889b6d80b2551b3b3f70feb3df848edf2beb72935129f7e4fba42edc5/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string100 = /bf352b6fb09f15ce5bb29db4f131baa128eb579b157e7ab140682891bae6393b/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string101 = /c46fd158ad7a0dbb616b1c0c5416bb77e43d5aef95869923d62097034d2a1cf7/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string102 = /c66ea235f3bec5713b4b30abb7fa938c472f9f66b1f1fcaacdf8b0e7c36a735b/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string103 = /c85dda1fd27eb34db30a297fe5ddfa279904579ce968d8fbe08d68a263c71a8a/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string104 = /cb5d63e74dee2d3908969d245f21722523a3a111f98a3ed13f6554cab98569e3/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string105 = /cfad83c752fa011d705c5a6fa65f0ea4fb99f56209a8b67f9a32629a7f36ee6d/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string106 = /d1409d4d6fc200f7f5569b844c0005eb1963a94a857ae4fb5caeb496783cca07/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string107 = /d166f3899cc7eb349d9ce4c8adc8f60e3a2908ed29ddf4a2e52e070d78e290ec/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string108 = /d341e25ece7b66006ffeae3f76194bb12a9d120368f0616e1ab58186dcaff932/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string109 = /d3ac20c9e1aa6062e8454e12f8dcae4bb66ed6bef18e304268196066760947aa/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string110 = /d454762487d1118fa84e8931d4ae93bdf0c39fa1f42deb177825eb8d94e8f989/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string111 = /d4a4b8c5f774ed28466d584b62cc61f44d2f89f139c7df2e63aefcfc203c2f3a/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string112 = /d6e656ad3fba0ef5630a6607f3b02ee5920085a8fc724e7617d959300d809cab/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string113 = /d72dd4d052362db7dee1bb2ed177279d4b4f6199288b7a0f9f377accc67e8f01/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string114 = /d9499b5feb59b820c0b9610da94455e1ef96ea018e170261ffabedda39044cce/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string115 = /dae86be018d5317f61477f260e8508149e769688aa642327fc6caba5786cc26d/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string116 = /db5df4b216cfc30f8a23337a875331dfa29a90ec6d1330aa834bd5eb641c2c6a/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string117 = /e2ad65bd782f8e3faa19426d408b84ca2d1cd0b4a3d12668febb8d94aca0457c/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string118 = /e90c0327bdf81bc4b5ebca4701cd2bfeb5f62a63c2e78e04756e3219ce01d990/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string119 = /ea40a6037ecaaf48b26ef67834d9142e426b84bdb9d7bac5ed62528e0a27cc60/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string120 = /eca2eda42fa2d4f71de8055f79066fce3866d22c8f38060ee98978341fd2a078/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string121 = /edb87b5669e9a133f18328402a89242a7844ad244929133803439e95201958d8/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string122 = /f00e2511ae291bed3ad7e08cfb4cb960ea10e14ef51ba15c928d5d3d14fdb09d/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string123 = /f18f551bbe47c5078c3e49718dea7287979b203fbd01149e9def64bbae723e4c/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string124 = /f5ebf3d481f604a7f5d301034f7868eb02bf07545dc2a3eccd755ca49356684f/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string125 = /f650e73547f22ce8b7503d31f62d2f8426c5734e5b25074d08527e50f74b0bdb/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string126 = /f71e8c4887a42cff058f46f270cc2c142ba2fdb4b714fd6c65e44a0ed09e2433/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string127 = /pufferffish\/wireproxy/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string128 = /wireproxy\s\-\-/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string129 = /wireproxy\s\-c\s/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string130 = /wireproxy\s\-n\s/ nocase ascii wide
        // Description: Wireguard client that exposes itself as a socks5 proxy
        // Reference: https://github.com/pufferffish/wireproxy
        $string131 = /wireproxy\s\-s/ nocase ascii wide

    condition:
        any of them
}
