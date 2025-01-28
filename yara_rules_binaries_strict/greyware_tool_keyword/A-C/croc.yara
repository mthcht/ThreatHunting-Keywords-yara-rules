rule croc
{
    meta:
        description = "Detection patterns for the tool 'croc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "croc"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string1 = /\scroc\-entrypoint\.sh/
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string2 = /\/croc\.exe/ nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string3 = /\/croc\.service/
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string4 = "/croc/releases/download/v10" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string5 = "/croc/releases/latest" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string6 = /\/croc\-entrypoint\.sh/
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string7 = /\\croc\.exe/ nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string8 = "039bd221eee059cf555d174e582b9135db9941d0d9fdab7aae1407dc928feded" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string9 = "0520c7e5daa571c831e5816bb1a65a558ebff4ce2e5f26b2a16efbe8c107d654" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string10 = "09f843b9740312ad9a4d084ed99c85cb589da4b78f434d141a03ded8cf052553" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string11 = "0ea531910d6893607e435bc0bc6746b10d2f61a1da0f2d59e67854f2ff2d4e15" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string12 = "13715a317d2d54c63f13951e7542a9d1809c8c2f9932a207cabeb26814f6817d" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string13 = "14f965c710f3a4a5d830c723f26867420e1c60acab48678eb82c9a3b68ea1554" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string14 = "16e9fc516f02b513ef7cc51bd1966cd1aad0f625d6f1763645b85f05fd50b840" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string15 = "19cf7f92ad4a5f458e6569830e2ff805e3fa50723e67fff5ef430fac4a40b62e" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string16 = "1af3ab6f5bffc4a367818ed64b823d9b54e63710a3566635e29f01478a680110" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string17 = "1c2d7d9badc2cf5a7c99d5435b40eecf5a7d579e3fa5f92f3ac27cf34068a827" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string18 = "1cc321e6be0a4b96e5661f3872f746da0873215758d5948bc7590779ac659a3f" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string19 = "1e8df455b02c3384eec7ea1f9c6c42927442634440738af4c68fc4f8c1941ede" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string20 = "28931b61113c322159a068082c977b510f424f6f01467221c36a7be1f77684f7" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string21 = "2ad44c7d840018470779d1feaf02584a602a30fa6388be5ef1c2800657b6de4a" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string22 = "2b47da18424e13db950d489cd612311163979889ae4272c3eac957acc5cff576" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string23 = "2c49f5d3ca26b2bdae62d01bee056f2d11f1093b675ad5cd5a902048c4ec58b8" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string24 = "304e4f8f45a5a18fc6785efbb4171b853bf2bddbdf4ed2e49c5f843ba53ca8e1" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string25 = "33e25c7c66bf6996e75bda20c9640cc175fcb18b9891f2ecc73201e0d4f74748" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string26 = "3426d131f3dc67cb3fac4cf53328d1510e71621f9ab42d77fd9db5dc6de50440" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string27 = "39fecd95598215f63b002a0c59db0455a2800e9c40430eb1a0d72a941fc24bf2" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string28 = "3a4b15468738335105fdb2b811e7eaf58c9daa764bcc8661e0a34e2a4cbbd7bc" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string29 = "3c71b38d49bf71f15200d7439ae3c99e46ad6b395db1188a597834920576c34f" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string30 = "3de0933657899d15dc795c7ac763f5b3835f55882392526dd4448d233fcb5392" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string31 = "3de87c7ff687b90e126d6daac0218388de8266c8158badf95c10b511cb1f90c7" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string32 = "3f6e46e4ac8b1b6da7d8527546f81dcff4b4077a4390c261c4f182abb2ceaccb" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string33 = "405609b8cafc3821bbb266aa2b6378d5e8ffe3f98ceac55afc3a18c61b4f97d6" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string34 = "415ee455fb8a1823252290b37409c13929d66e1176efdbcbc02ff289c3151e80" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string35 = "4264273bccb4971f1fd61b50ce4ac53dacdc5f3b103954524eadfa8c061e3351" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string36 = "434de407f7f00410d2413e6d854a70380a5d046fefc918170cb3347a41ba38ac" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string37 = "47a4c440be07a166b6b89e56bff1ed3df43f4398838037c50e2c8c937db92498" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string38 = "4bbad7d145fa96ea1255c3f3457c2ca621993be429095cea398e98625c59a640" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string39 = "4fe0b0a017cedf51e40742e6460ddd479eb4a25e31356c02885dd4e7c5b65b17" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string40 = "4fe9718a0aeb5f9a05f662647a12781ea44b3640526615e62b389e76682a5d2f" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string41 = "546c3dfd281f8f06aaf64a0fedc31096e2af287e2fbaeffd4c431ed6a6c4d28a" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string42 = "59ffde09a3efbb8259e3f5523aa1a87802c3db701f050cc411ee3774cd78d050" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string43 = "5e396778b4dddc94afa030aa8cb23e4c2de4b9f2a9bc3a8ee5d43c0567c8c4eb" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string44 = "5fbee208e22c036434bb65f38e01529922e5b09ea0fc55f5d870198e8330ad39" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string45 = "64d74833b7399d52cd90584314ceb3a59049d93a25a3743602224888fc39aaaf" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string46 = "665419215556b97d2ebc89e3b1df2222d848259ae005d0579b1311a93d224fa4" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string47 = "673bf02f5e5f536474cb96c78ea2da5f992ffa8d9b98021f7f569c185305cad1" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string48 = "68664083956f7abff8fa9b471ae0f8ff2a5ae540ae292c3ff780411c0f8cc072" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string49 = "6a08db58b1d1cb9244a48feeaaefc6097dd8a0fabbab0f51a83ecc2b2bfdd36d" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string50 = "6a1810c50df3afd5f476e04c19b361c5802b890f1c06cea39d4c573abf3eaf16" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string51 = "6da1f7a8087575b0580228caee8d40ba7d7fb078d7f18e627792b6cc862524e7" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string52 = "6e6c21f7a5070f2af43febe26adcd26007651b928f335ac66673e955c39a4a29" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string53 = "6ea5a9fb8f4ddeb82111ebe5583c88e0d483d2b4d18f64cbff7530be3affd5da" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string54 = "70a4631e43134af49d957c6e4fa3275383c1543f5462d6230f90b2e446189efe" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string55 = "71add603c1e99cf23497d2c79e317d27a08c9ba7ac8afce3e36e48b080a4a456" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string56 = "71fe9b98c24f53cdc002f7efde57d17e08288dee084a98eed639bab982d9cd26" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string57 = "725f1d7143aa95e149333459b48d7b538e98b65bffb1c4005eac8f890e84e34e" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string58 = "7287fab98c5650ad7241959233347f346053d691adeaf4ebf5235b9cb00bf711" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string59 = "762433cd21a41e39e1cb40721fdfa40b560d91ba587498d1d5e71a0c73b2e752" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string60 = "7777762e76bc6c0025effecba1efd3028fe15453c4375a9fb63040831c8bcf33" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string61 = "7939cd653bcd9023465f1e4110a7204722d42c08252eb019dfeb717ba180ccde" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string62 = "796c2baabb9126ec5f2a3006803bd5e3aae3084f1d5578de312d0f7035094a2b" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string63 = "7a4ccd5e3e612d5967167ed948cc0cb2347765783e3658cb747fdcbb559b7955" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string64 = "7b76cf1713a14ce545ebad381570cce04a32d41d7535eacd11491a61d77c67a6" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string65 = "7bd94e75f734f3d4b45758e87eb67fde300992db436ba11841175a334cf47f11" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string66 = "7d5975b4ed5d6f2016b617c08b6e00cab52db4f90dc04cd5e724ce02fb334618" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string67 = "7e2938acd4f92c036f1e72559acc262c60342f6e96380d2fa451b960f96be6dd" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string68 = "8014a77fd36652a4d7bea8fcc66f9fb474093bb5a058ac7d7d0ee5b9ad2930de" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string69 = "804201a4515437b3b24ffddc8aaa16cbd0640b4279237e0b162ea3e44c79e67f" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string70 = "80b49c2c746081c110c0d26c8439f3d5915f3a40e6eda4a9dc004087f0ea9707" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string71 = "82adb5af26e4d48ceafec3852889db12d4de8ce046f196aea425f978bdb7fa7c" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string72 = "868d273ae930d63b3c437203040a3ab36d2f7b355a33c1b2ad13bf3264a35747" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string73 = "8a40c683b0192db6685d75115b4d3f3663662fcd7ba4695799756413f31dc43f" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string74 = "8b831af85f7b48f5a1a2f461d77bcd70eeb92a52ecda38993614adb67f3f63ae" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string75 = "8d76b2ca80541dc0e19a52323d3321260861460020bcc8db2b48de7469dfce6a" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string76 = "8e4a98c04bf869e228ca6d7abf130eb2307aa41c6ac920cceb31591f485c1a56" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string77 = "910a62b83b8cf94db949509d93246ba48c7ff85588c344ddde09a7389879d2df" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string78 = "93f78fad351a6fe69b67f2802f74d96f1c7706d364c37eb4bafcbe4d3e3e6bff" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string79 = "940b828e6701c3692a43eb30c3adca158194098f8ad78d7685c05d39b14d175b" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string80 = "9468c5f983186a7d50d82bd7591bd2f6080fbb1fcfb63c0a2ded18ba359d9f2f" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string81 = "95223c891d9b253c9e73803713ab32b7058674d3db6b305ea5a035d84713c9ec" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string82 = "95f26fd9f185436a9dbab6c31c094bdf789405e7297aa799c672bc3f007a24c5" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string83 = "980b74c1c6056bf545ab7bcd5c7699162b11a653931e910e61d8649f7a2dcb26" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string84 = "9a94ed9833a76fa0b3a54b54d22d28a7afbc7061085e6a4a136597f272857955" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string85 = "9ac9cf037b5413fd2fea88b73a4f1d412b41d64352cf4e9860edf13bb01c7ac3" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string86 = "9b02d76d0ae71f8fe680010e3e9174c67c437ae9d76bce7615be4a3161654a0e" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string87 = "9b61fc30930c67b9afd24f6e028579bb81f72c3fe750cbc9aaf747c233effa70" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string88 = "9cab3486e77ce43ae5295dcb724e1a25b1db2f8ea10bbbb0cd0b81709fc20db7" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string89 = "9e1cb4b50f43e8d7041feb056466e078b124b485cbd708c98604460314602ee3" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string90 = "9e1f0fe87d08779bfcf0b5253b92af92250dbd2db6f99d6ca747510ec87cf308" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string91 = "9e4c4e615928ccbce23648a08fc6861be46474c7effbb9fed5e607f5f2501abc" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string92 = "9f78f3485dab3247717aef7f603bbeeaa7369f1b8bbd9acd1c4416f25d956493" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string93 = "9fa8e04f74d61da484201db9a063cc22f95c76197dbe31326c73ab7c6792957d" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string94 = "a05b247f1368ac7c4e08b63300ec27ce5ff6e8cd306c0f7fa75eff9e89d0fc92" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string95 = "a111b6db4f1609e4d1c0f03d4350918f7cba997edda438c159fed9ababc2057f" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string96 = "a2a15e31637a92f08e230895fff885e377a611ca7b422c2fe40abd6d7e29dfe6" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string97 = "a3441775e9833939a238c5b13fe8564b225ef0def7983fc9ef1746e48f3f82ed" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string98 = "a5644b66bdcff05e69196f812127199c85dad1e65a34d62a8d50030a176b3bce" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string99 = "a6b04710778f15b52322aed66b7e6dde036af3a8e208ba65e7a79d905bce764c" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string100 = "a892f70b16b239a1f6caea1877c3f5d3747c1b3e3f5d94d49e21050d5b873ecc" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string101 = "a8f7aaf03146c6e41799154fccf90e1ac4ffa48b76d582accfd0dd4649b1e652" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string102 = "ac28dbde92097b0e44afe3b47438c963845d65fa88aed27136ebca38870adda5" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string103 = "b0daa38ea704406f5eafe4056be67de1206dced6333c01c90f76441aa227ee21" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string104 = "b421bac88d296432b6b92005e1dd0c6fc94a023a54afdd0d4965693d264cfd5e" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string105 = "b5e2d8796b19967b5945d040763d9d140f3e4c0393e4163ca6acb43666e998dd" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string106 = "b7a85081d3f3529c2d0fc98596499489a27654917c1188f5dabe9ecdeac4459f" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string107 = "ba9d24e28c6e24740fa1a9c49a09c8c80c12b367eab4b550afb6cc4fc08bc698" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string108 = "baafca947c72c36658ecd4593869100d200524ece1248b98234a44e6113bb6a8" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string109 = "bb10b0d3cf12dd5a2038e765473ebea32bef4e2ae875cceb9eab281695456f14" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string110 = "bfda2d9bd0610c660bc86497f79ce1e0fba9925e4e04bc1da9d19e01e74986fa" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string111 = "brew install croc"
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string112 = "c140a7c12752ffe61a682b74970758d6878c99b5b2581d0b423a0ec051dcd557" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string113 = "c485687562cd2a0bfe11c6ecb17a052bbdbb3662ae1faed3627718cc5da68af5" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string114 = "ca6ae284ec3e1dfad347339b5ebcd71fe6f901a359d1dda672bd560aa7768ba2" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string115 = "cb03a9577b8d7803de33676b9aa5317db4a149bc0ef45ea3971c71fe061d0ea7" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string116 = "cba6ba250d94853df4e8074831cf8f7db13d559623b368291a91f29501888edd" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string117 = "ce5e687fc19c3f437fb7f27525f3b84919a24fa16b0db787fafa36b9958c85d4" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string118 = "choco install croc" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string119 = "croc send --code "
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string120 = "croc --socks5 "
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string121 = "d1c73f2571c1860b571e45fb43d46dfb7c73342cbd528b29a79a4cfda3f6edca" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string122 = "d3230193b881c103cfcae570a22a2f1a742c94fcead8448cd55c47ce820c09bc" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string123 = "d50c5321bc4ecc9dc77f72e62e4f2456b4501af29f5d35a0d402b887a6f096c2" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string124 = "d57360ea543abdf4a3fa0b150ad4e0f2ca506f3d88c2c4e807cfaf684d9a73d9" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string125 = "d5a54de1522f18cd135c4fc069fb3f2ee4a12fba0cc17d08a93215048df45189" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string126 = "d9032c75bd7e249aeb2df614ae73f50b2a488008efe492e9a6709e97bcf69da5" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string127 = "dcb311e963ca2521c5e08f9701c7973043a6af15b7eba73595bc31a43dbd9abb" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string128 = "dd13203ab3267c855d002587f7be0509403d9d199f3b8f1f482b275189bc203d" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string129 = "dd71ab6e67f428fbef9937631774ab3cb08102fde4f9cc4ec5a8c27e29a18a65" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string130 = "dnf install croc"
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string131 = /docker\srun\s\-d\s\-p\s.{0,100}\s\-e\sCROC_PASS\=/ nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string132 = "e0502577758a772235d8b9ca555e54fdca4570ce4e61a7afc84575e3b95e6747" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string133 = "e0fca5495cc0f8c293d185530a3ebd81f9a304c6804c4d0cdaea8b6b8ea8513c" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string134 = "e1899d929b6435421aa16fbbfe75431a8cfaab9a9f751a3a6594792a4a75f517" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string135 = "e1d7927c9f4b7bc9e5079ca22857b46ea5e39fd4d1fbe415ac24c12ec7b912f9" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string136 = "e3c1c5f76c339c8e11dc25697e8b9b7f7b5ad7c1cf6a63eba8e52b0d6a5f33b5" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string137 = "e66d1f7ddfdcd26036e52c644284857b23144ff7b0644f9d66350b6996659c23" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string138 = "e897afa92d40de471b6e4df62b9ec0b9039110f08a4c26324419bed5309d3f36" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string139 = "e92cabfa2aff26a45e7dcf1b7156b0b24ef53a96bff707812d64c476c9a57f7f" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string140 = "ebc18f1f5581d5c5da72bf1c847ec97c2a32156858de8fffb9e6d5b0bb96c195" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string141 = "f23d82762095f7fd72ef625aad0d41b0e70d9e29619f72e91c2c140464d71fe0" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string142 = "f3f224ecc4dc019bc4c93de49c408db2be3b73fb62eb9aebbe1fe2715ee98547" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string143 = "fb45b07601cd1845509b61be66e2cb65ba43a915d2089c3a21351134b66a76de" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string144 = "fb87c3973cc69caad85bb39d56bcb5abfa11b3bb4772fe1edfd1ccef9c01d515" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string145 = "fe38147743b83a8d6de300d7fc5d7eeb6478cb6de6587de05e6db2ba9e4d5af7" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string146 = /getcroc\.schollz\.com/ nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string147 = "nix-env -i croc"
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string148 = "pacman -S croc"
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string149 = "pkg install croc"
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string150 = "schollz/croc" nocase ascii wide
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string151 = "scoop install croc"
        // Description: croc is a tool that allows any two computers to simply and securely transfer files and folders
        // Reference: https://github.com/schollz/croc
        $string152 = /winget\sinstall\sschollz\.croc/ nocase ascii wide
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
