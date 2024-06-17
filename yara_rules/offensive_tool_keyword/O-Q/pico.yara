rule pico
{
    meta:
        description = "Detection patterns for the tool 'pico' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pico"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string1 = /\/cmd\/pico\/ssh/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string2 = /\/pico_plus_user\.sql/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string3 = /05acf5d2a8e06af036dc6e434e540814a8632c7a81601f912092f8b2f12c6ed3/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string4 = /061f3dad40a1f13fc95fd287fc07408375eab69be817d75251e2619fabbd11cc/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string5 = /073a84685fb4031ef1d19df47b3e89714ab24bfed80ee48012ba300e4218ffc2/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string6 = /08bec0a0da412feaad0cd339162179c50edd5bc75a0fa1d25fa95c00f2437f85/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string7 = /08c4e8f76bbf766917611b1d53774ff6ac69edd31aff71ab5c344d59f606c4e9/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string8 = /0999ff434753baea877027af71dc4f7ed5866e3647f19d9707063e3a0a7b61f2/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string9 = /0d8e9a6a82a88a754aee39087957d95fa2cf4dae8a0b931e61934b69bfc4c491/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string10 = /1ad347c4e88e8425849acdf2ec2f35e690123f7eac1d16355df57b9f4d85632e/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string11 = /1ae74ae5b25ae884783a0bca12f63b026a78c123a36ba980f1f931087024354b/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string12 = /1d74b18520b9569c5c602ee48a995069dddb67e6343ae2cadce691f1e72609d0/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string13 = /1ea5b4bca8da1cbc3fe7cc396531423ead927ea709c9b5d5de20c931590c6a25/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string14 = /26b7d1e0b6ed36874a1b73d5077af3778eb5537b842eff21e3b1be359154151a/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string15 = /282664f0cbf48838d9ef0321b748721b14dd40948e0f16babdb31e458e06dbe6/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string16 = /289451cff336966b875ae92f5894b0b7daff939425756ba1b7f39b7e9eeedd0d/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string17 = /29b6ac2ea4feac6530ab3f5401c99739ff8eea1f32f0a120fa971a9cef9bbfbb/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string18 = /2c64db7c942c64fee5fa3ec20a40b21172b91108b4d70a4db92edc5f6ae21d78/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string19 = /2e21672308bcb51cab1a41253f0132ad82101d5b24c33dd1fdad89b4bd619dd7/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string20 = /35a53f161401fc9f654cb82ed45244023ccd22315a638e8ec2b37b6ec814de80/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string21 = /36c21ec0ea2bbe57193e5f8354f4be046558921bc3231506f99700243ca18518/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string22 = /408a69941c8239608571acf56048f603118e947c614c14f7679f19317d4c977b/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string23 = /48e14cff5c1fbf0bdd959c1d8f6dad4d6b38aebc29ef8210fd0ac7156b67b468/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string24 = /4d76e208d1d7d828e35725d30cdb907cef2bd52e2c5cf9ec4290182f4464d2e8/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string25 = /56997e6f1f96b6ebc89a03491b3f97077a3352730566c48bdb02b4d59d284001/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string26 = /59ec5f3ac06dc1e082a3f28441105f4c65384a4360070c725452311ffc6f856b/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string27 = /5c1ced06b49c8595e1191004994c0b82de8eef82559776faa1dba19240c76dc0/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string28 = /5cee697909834727bc7a7531b6e32defd302d40a7643fda5ff9877e24e60d4bf/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string29 = /5f34b6621adfd6fcb5d9bed2972fc7f7409c04775ad1a11b396715784910ecef/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string30 = /604f76c6478fa080af7052988d643c407a6851d5b4ed0a30858a54d6bf010445/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string31 = /68893940dc6f3230bb1e6fccf92c698bd7445de283e0d5739336b8b7e471f6a9/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string32 = /6b1999feac59cbb6e99129a25ffadff086bd232d7bcf05d4e6e004ce2901a3eb/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string33 = /6dcf6d012c1eeb396082ea834f963cd8740babc71d3fd7114664d76dd5975d9c/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string34 = /714f984be43793682fc8edb7c9865bf864c8051d83aa08d197c5c0bd7d96348f/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string35 = /7678743a1980ea6c51d430208bf80860d45abf792864ec321c7f1680eff89746/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string36 = /7b8eebc200136f58a721bb5112df41c3af8ca87ed505e07787610d3d8e7775d9/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string37 = /7d6717ec16ee8a51b0fc81d5c762f8735211d13c8be9476c2e75c3f5ae42a478/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string38 = /7f3e3d8e8a2f6be44925fe45ec065c0d3f5d8c578e5dc436e677462d53efb2b9/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string39 = /7ffa4105462bd53c5b1632324b3e7ddb71b18b57e8ecd60fc849b433a036198e/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string40 = /816b85da5902d45e9d18f04e8f2e731719ee796e619456ef9cecf365bc79ceee/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string41 = /8a0f503edc5f450e94323d0d1cc10fb2f199f6bafdad02f382c46f5b501c98fb/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string42 = /8b2dc1f28bf0d8eb2501759807524c08778a8c4140e3af9f16bc2829bd9fdc66/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string43 = /93a50251b09b5dfc88fa583099e0724815099269561ca070dc823b4dd0be536d/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string44 = /956f0e02e10050586c0a0fedbf9da70b2204726342485f8400eb0804eaadeb6c/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string45 = /968cd73ac2f46c39aa9fa8fa638b63f6cfe07f23ffd9f39eafd1bef5bc818462/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string46 = /a0c82b68e731b303cbb379ca1bab45110c65edae85dd183bb66c55b0a7f3e9fe/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string47 = /a39094b4805dbd909a8450973d690313091cb300d184c8633b0a913942d0fb69/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string48 = /ac26616ae7d5b4516fa1a182a49dd3466e337a6fc13a4373f9cf3f973d83a173/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string49 = /ae35923152fc85dc696a1af8f5715091b5ede761fac61fc5e89f84a2f727b21d/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string50 = /auth\.dev\.pico\.sh/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string51 = /b1b5ef389275906c96e2326deb09d4eb6576fc692d8425ed0779a3acf3e1ab1b/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string52 = /b3d610e1b65dc16e081de173a8ea83f9f0c40fb8bb5cf73e3206294b013485b4/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string53 = /b8f44b3631dcc6e055b710d873486f3b3385ea06f38d160a7f6da2d7e6c809c3/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string54 = /bb8861d4a96d5b61c018115dcfe61176d12097e271ac1d34860bf50fe89618c8/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string55 = /c09373970ec5bbb6a3dfd02d13b233cf733501dbb92f3550f9168864087bec74/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string56 = /c8bbde78c6ad9fb5501ca1967e813836496498e0592e7ca77f7d6f9c43ef96ca/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string57 = /d3fb208381f7b76b1dfd3250b98fd258bdf1a1d77d721dd52b19558968910cb1/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string58 = /d55db7d82a8a8f375172b9a7e2a1cc01d4a7401266e6ec2ae1c6e179c2cf32ac/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string59 = /db9b4df43af0a73b96453a0e6967720e794884f48abc60d3d8743309c3ae759b/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string60 = /ebe927a4481119e426d73ba93236206922902cb1a5eb34a85be60294c81e4b0d/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string61 = /edcc3c97475aa95c19c8c08124fe6b9c5aac05ce4f253af391b7b1710d04b336/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string62 = /ef2eab4d2badc48463192b2eef76faf323389acd8622270e16e473a26bed88c8/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string63 = /f361e6e5c74be6d5ee9c3cf578d4855280b512ac95988f6afdcecefc917775c2/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string64 = /f6192766029db752408501c6333685fdacc0d4d308222bdea9f6c3c5dd9b31de/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string65 = /feeds\.dev\.pico\.sh/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string66 = /feeds\.pico\.sh/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string67 = /fef899edefd08d58272e77a010c77e788fe5a0ea114b729908e928d07c78ae40/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string68 = /ghcr\.io\/picosh\/pico\// nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string69 = /git\sdiff\s\|\sssh\spastes\.sh\schanges\.patch/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string70 = /hello\@pico\.sh/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string71 = /https\:\/\/auth\.pico\.sh\// nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string72 = /https\:\/\/dev\.tuns\.sh/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string73 = /https\:\/\/minio\.pico\.sh/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string74 = /https\:\/\/pico\.sh\/getting\-started/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string75 = /imgproxy\.dev\.pico\.sh/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string76 = /irc\.pico\.sh/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string77 = /linux\:feeds\:v2\s\(by\s\/u\/pico\-sh\)/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string78 = /minio\.dev\.pico\.sh/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string79 = /minio\.pico\.sh/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string80 = /PASSWORD\=miniosecret/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string81 = /pico\.sh\/irc/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string82 = /picosh\/pico/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string83 = /scp\s.{0,1000}\sfeeds\.sh\:\// nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string84 = /scp\s.{0,1000}\sprose\.sh\:\// nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string85 = /ssh\s\-L\s.{0,1000}\:localhost\:80\s\-N\simgs\.sh/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string86 = /ssh\s\-R\s.{0,1000}\:80\:localhost\:8000\stuns\.sh/ nocase ascii wide
        // Description: hacker labs - open source and managed web services leveraging SSH
        // Reference: https://github.com/picosh/pico
        $string87 = /tmp\.pico\.sh/ nocase ascii wide

    condition:
        any of them
}
