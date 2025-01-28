rule windows_defender_remover
{
    meta:
        description = "Detection patterns for the tool 'windows-defender-remover' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "windows-defender-remover"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string1 = "--- Defender Remover Script" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string2 = " GOTO :removeantivirus" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string3 = "\"DisableAntiSpyware\"=dword:00000001" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string4 = "\"DisableAntiVirus\"=dword:00000001" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string5 = "\"DisableBehaviorMonitoring\"=dword:00000001" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string6 = "\"DisableOnAccessProtection\"=dword:00000001" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string7 = "\"DisableRealtimeMonitoring\"=dword:00000001" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string8 = "\"DisableScanOnRealtimeEnable\"=dword:00000001" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string9 = /\/DefenderRemover\.exe/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string10 = /\/DefenderRemover\-x86\.exe/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string11 = "/Remove_defender_moduled" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string12 = /\/windows\-defender\-remover\.git/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string13 = "/windows-defender-remover/releases/download/" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string14 = "/windows-defender-remover/tarball/" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string15 = "/windows-defender-remover/zipball/" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string16 = "@set defenderremoverver=" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string17 = /\\DefenderRemover\.exe/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string18 = /\\DefenderRemover\-x86\.exe/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string19 = /\\Remove_defender_moduled\\/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string20 = /\\windows\-defender\-remover\\/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string21 = /\\windows\-defender\-remover\-main/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string22 = /_DefenderRemover\.exe/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string23 = /_DefenderRemover\-x86\.exe/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string24 = "0105d13e4b33829b13ab839a9cad10f135b65528af0030a20060a190b3e2753f" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string25 = "036fe0cc4697725599694442e4b0a45ff13fb306dc7d36759cdcc4b2d0443104" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string26 = "03ddbfc72964806b084c5fc7005c4f3768439da879b43817c853a2a55af82e31" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string27 = "073f74ea0d5d2805e2255bdfc5cb697f5292c5b96ca55791187eaaa7ca6d3ca9" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string28 = "08d43f94bbdc5f8b1ec034b09c6d2536d50dd92f9132e61c4ec85a716487c6ba" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string29 = "08ec751857b68b0501f0d810f45f9020e6afb307ec536c139a1801e95d870be8" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string30 = "0ab70dccb06b2a6c06c16dd3aeb00140c9eaf4bd178d4edfd3ed662af3fcba13" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string31 = "0baa85ef3689d4e9c15d6d64dfd4e4b633db4af6bad347eaf06a2f320d82074e" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string32 = "0e8eff9d7c2a6d2cfa40a7530753cccffc959186c9e1a89eb623e2dd5bdcef6d" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string33 = "13398b7c4a972fa76c0e79e34fd4df50dd08452e100c9ae6cf44c35e61a49745" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string34 = "193aee65af4af71fe6194ac4c2214a27d78706558c25022f018ed3e28bfe7670" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string35 = "19c09fad30c786cc22fb38d3f97021c0b35aaa9cd288d44970a45b5d1cb86070" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string36 = "1af3fc48ae5984de558e620579cba8421fc8501a7494e4b0ec410c8caf302a85" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string37 = "1e86687255a3e8b507716d855768ae9e6064152106c041a6aa4940bcafc81079" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string38 = "1ef9ec4d4ce0179495d5293ec8ad7a9bd80b5f83652b178f1871258cc78a0a9a" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string39 = "22ee00e26aed0e9dc83b202584c5f8ea81147c64d85233d1ae6b5929c8351ed5" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string40 = "2b4d99a0fed0b109882531b7feab2545d45854c699d2f274bad28f256bdfaf78" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string41 = "2b5fb43fb67ba0113f19691f759628dfa46bb2fa568fb683bda8e5c4b5b6df06" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string42 = "2cca313664b8df442b02f4115925c4803262da9df7f3efa84880357b16333f11" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string43 = "2d9b32c3eb9cdb1b9574f2e462eeb5724ae761adab5780f6d6168aea828c19b1" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string44 = "2f1eb89e5ddbc2a72831e7ac58e9cc823d408affa6f60a35c559bddabd6eb16f" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string45 = "2fef430e1b4c0fd66bcacefb5b90e7ea1b036dc377dbaa0d5543e429b71aea76" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string46 = "315bb4e894fc10642514693e365e7a5f6df0e0c12b21c392aa983da5c8c49974" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string47 = "31afdc793da401fdfbe73addfab29166c47ff9c9e39a82661f621ca43a79c6c4" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string48 = "31ba179b08e80d07e8bfad5c7eb4e1a68a7ccfe81735e4807257c847b5478d6d" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string49 = "37070edf6ebb0124be0a6c2d8b856ecc73a32149a3b0add1617e2280abbd236e" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string50 = "385b94df8c0ad36fe074e09b69c06f427da95958555690ae65a51fd913f5a4ba" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string51 = "38d181fa41f6cf0a8125620801d745db9f0d479e2ecc130cd136e9190b9de52d" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string52 = "39f4e1678adb3bbbf60f3c3a394f30a0c85d17e1db7c2f10b9815c2ebc5ed314" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string53 = "3d5c8b987186dc4ea84388408e0f0cc8b4026bb509e4ee4d8f8d090896ba1a7b" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string54 = "3f2c295013df2f758d84f70a59f7510fb1b86a9e01017a0865531b6637c0afe4" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string55 = "403b4508661f4fe6473ee1e56dce4ed39f563ab0cfcdd74c3d1eceb86cab62a1" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string56 = "41efb031f13c00affa750865d6d2bf965ccf2ded9a50c40a5ba628b97ee0cb12" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string57 = "42c99aa68fec2ee65d35559eac9d40b572bd5870c59b28e1f76da076c7ac4636" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string58 = "43299df4a5e2edbfcc0443c9555b10a8a603015a20213f63a7e0e2b7923a4603" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string59 = "45a2c28d5ee54ff89dcdb82fd23110e353a740277ec8d6ae0683a111877324cf" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string60 = "4a9dc2a031cf05b8ba61fde0462db7942194297b4e763e9d85c57d99746a242f" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string61 = "4bdff76e56960fe9ef5cceb930d6669ec9e04ec8dceb9b5c856306abc1862f12" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string62 = "4d2d4f8ebeeecca1e823c2f63975a959da91840f681df53243c6caa16ed67621" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string63 = "4ddb624f4a569274b1dbe946a2a7c6c4bd43d36183bdef148814c228147b2fd2" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string64 = "4fa537aa8c3949d9fa489c05e50c781a69620db8ead08cbe0538eb9e7d8c1016" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string65 = "5071f02457717295c663c269c01d40b9e789d386281c3faa47ab1e88eb9fa7c5" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string66 = "529ba3d890cc8600221841ecc3fd4419c4e4c6cfcf655df163da2805a57db7a5" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string67 = "542742cf1661a2e40473ffd6e8f3a4a1035a6ad31cd5ac6ca90965ef03646f27" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string68 = "565e40d59cf30f23587c75bc33d9f452ba9017650f4ab259af77b1d219bdb19d" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string69 = "56b8e87c6016e38e0c6700b97b848441e89777842153de74813a445b3e7fd5dc" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string70 = "59c066aafc12f8aafd28d1b1667c5e3c8bf50ade2fa0660e18b484aeb1dd8fae" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string71 = "66cf5ea7e6e66a06e331c24e6210453c39788f86973a3078dce8324aaee11af8" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string72 = "66d6387cef13f58ab746d452dc68e0f3e71d509a50a4f7518490fbf0cc16e3d4" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string73 = "6bbcf0ee5f4adf9d64d66bc8457ac414830c869ad8a688c86099b41b0328a0b7" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string74 = "6c07205f852af6214909bb887cc94df51f6dd4fee6d9b83c292d70a0970b0bc0" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string75 = "704ebc20fe0c7678a2b73d97ba6ad2945ece3a7d35ba0e0a394b629570af00ca" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string76 = "73090c936c651512967306fe08af95b5ad4272012902fa53570806dd290b02f3" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string77 = "73939d01fbba0a642ae8ab2df914bdae45187cf0cf131ae2ca5d37c05e8181c8" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string78 = "78dc269070acbaf7981717c584d983cba142abccb2c7efbd9158015147674e77" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string79 = "7b4abcd75af76bf67bc0028fd42083c4dfb81f4b27ac3e7b54bacb16436165b4" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string80 = "7cfb2df4376d51979916036569f38f42bb862d122b708e3531f16ecc6db08e71" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string81 = "7d5785c1760909ac5dc68ce57aabcf86af2444ae42e19b568eb1e32d8a414913" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string82 = "8361ec775f42fc269a4ff4ae37da23bad4988de8846db0160bad66d39d9b1365" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string83 = "83da7d9d86d928f9c0d2366663a04156ba92932b75b51ec53339fa67eaa87ebb" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string84 = "849e89c51512e60426cd9ec659040cb18bbb49a31d463510f176d550b207acad" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string85 = "850e81d95da8437a509398bea9d751af6c69b97799b64042041c074bc34e6659" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string86 = "886913aabc03e8863c9fa20034054a2fc289c8bfa838e5481d5d7e90e1d043a0" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string87 = "8a30a6a44efd71aa9a771f4d9864be4c3c9d8074adc828018ce774764e8036a9" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string88 = "8e954ebb0db4a599f3257b78ab4aec73f4e31e49fdf1e8da9b6705ce7cf84858" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string89 = "8eedb89dca530ace7157ce9e1842cf3cfe4bc61830b4f23e03fb992663f8c05c" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string90 = "8f0024607c41631601d00be5be8363412af06193353d0ae20b749f3843da41f0" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string91 = "90edb0f25788a09d269aa4f51eb5a7e99d8e95e14ca1f5ab25a958dfcd5fc313" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string92 = "910c0a93a65b356c7a9534332555c560285117859d771781f9aca7848a25f336" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string93 = "91abf8042d65f120fc30af7618fd310e44e54f69b390ec8f08bc8cb2c251697f" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string94 = "924b6dd931df29e29d17c91a5097a040661e17d6a8b404a1d0ee6ad9b0a97473" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string95 = "94f363f8d5a0c96bd72906bf5cef04d1966ad6c1fc99c80484ad89e10b20b8db" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string96 = "9b379b8478d9ec722c72d0eff669e132dc52c44e8d27bea832b6fbe6d4f00f11" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string97 = "9c098d624b4fd2ce42067a75d0d5f37e6d580e5430ee68dea36d4325e424f1b4" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string98 = "9caa9d970f801818ebf71838c7338d726bdd70fc7cac343bdb21512c3bd6ceaa" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string99 = "9e373722530a78ab12472a38e0b6834a31162c25eeac4f02ce9cdb755e1effb0" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string100 = "a13f4672fc13262b372d0ab5c186851f6bb2ec1a76a68f1eb3e85ac9478f2c91" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string101 = "a1ca98f25cf4319995603b9cf1869da4a0a82c1747e01fe4714d1c4b5faaeef8" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string102 = "a2f2705bdc56aa0bde9c27639f9d8d430fe5151140a85feac95ed6537655fbc1" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string103 = "a5e835c60f19233f4adf294821bbd82663e185ccd38444993e7be983235760af" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string104 = "a6fa768c4964c328c748558627c20c2ba455e589a1b87cfa3911d197da1688d2" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string105 = "a712ea7de1e93b1e8cf780d6e0d042fcf5e277171f6cccfa5d48e20a48a2ac16" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string106 = "b40ecc66931f17246fa3d7571b293d86cdff0581364efb7405c5cb71873fc2a7" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string107 = "b88da2e2ea72952817c28091798efa4c08bed068b6c399799627d89a74968e81" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string108 = "b8ca777d50193a7734680db80690c6106076a9b5b279300a6a52bae8564dad2f" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string109 = "ba9340aea52ef7176b56c69287e191d7919e73fb5e59bc6b059136740f375dc6" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string110 = "bcdedit /set hypervisorlaunchtype off" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string111 = "c44037f720d823a5d8ef14efde9fd0b9fcf5cd36cf0db159e1ae67ebac1e3b7e" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string112 = "c7bdcebe60356900dc4b4f8bc8b75acc1536df33ae7a1049bfa27192b8c62d0a" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string113 = "c97c3cf0f90fa6725324159635d3713685c751cba0ec854501c3fc979a349647" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string114 = "cd0b70d141e20db2b6ea5fa1c07a5310767f510a56ae8af7724fbd40f263bd6f" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string115 = "cde13befb711bf876f0952b847bf8d5e0cc58f6ce208ae54be29411a877f158d" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string116 = "cde5c0d1b934fbec6b40a6f26c383ac926f27f8f00937313699d2ef5bf671da2" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string117 = "ce137e86b9a64ee2424a5da774398fb01a1488c50038fcc883c8bbcb2fa82ea9" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string118 = "cf9e538aaea081090e945093f69919d1a76c34f0200ffb1a61684273bf43eba4" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string119 = "d3fc31e347e01560159e4a3955f4ceca4ee12b06a2f56c448ce5d10c9c8788cd" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string120 = "d459f80368ae7be9d0cbd41ecd25571a25b1b3cff3e0280ee9928321d948f689" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string121 = "d7d86b7b1b8535a28ce0bd897ef6e6e5ebaf6e9c153bbb6052f45cea58836f76" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string122 = "d876e3d39079bc0dbe6c171c3354b894f1c1f439ea80e335c401f19792efe064" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string123 = "dbb0f54089c689de684d365df493caae0d20771d4e486060087eaab5fd3f679e" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string124 = "dc8b8a51cb8c46c8a57a596d9c970eed5288b0378418c10cb98b5db399513b5a" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string125 = /Defender\.Remover\.exe/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string126 = /DefenderRemover\.Phase1\.exe/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string127 = /DefenderRemover\.Phase2\.exe/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string128 = /DefenderRemover\.Phase3\.exe/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string129 = /DefenderRemover\.Phase4\.exe/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string130 = /DefenderRemover\.Phase5\.exe/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string131 = /DisableAntivirusProtection\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string132 = /DisableDefenderandSecurityCenterNotifications\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string133 = /DisableDefenderPolicies\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string134 = /DisableDevDriveProtection\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string135 = /DisableLSAProtection\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string136 = /DisableMaintenanceTaskreportinginSecurityHealthUI\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string137 = /DisableMicrosoftVulnerabileDriverBlocklist\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string138 = /DisableSmartScreen\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string139 = /DisableSpyNetTelemetry\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string140 = /DisableSystemMitigations\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string141 = /DisableTamperProtection\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string142 = /DisableUAC\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string143 = /DisableVBS\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string144 = /do\sPowerRun\scmd\.exe.{0,1000}smartscreen\.dll/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string145 = "e241be711b4e535d9275bd5878d45e4c89bf4e269d27f1742aa9b2410d68ebf2" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string146 = "e3c47e6fe49e0f3905ba47ee21daff40a53ac9c2d18eb452a27812ef054a4cdc" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string147 = "e7ccd3ab3e214e8dd902bf044b6de4e5cf03f6db68476995d5cd02ba4e91067a" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string148 = "e7ce97b11adf6ae5bdf2893583c1de12d1459ced27c9a78cc12282ede35b924a" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string149 = "ebb3a940c6d104730532897e9e753cbeead3ad059186e15dab4f403d6ff0acf5" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string150 = "ef71783c18624e5c80cae1b445b545eefa0338e7736b0c5e9272f6dad1cb7092" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string151 = /ExploitGuard_d\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string152 = "f1168b6e2d5fc6d6edba534cee25fc9a4d9b28eca6435a9111449ba617626882" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string153 = "f2d54156ad1c855eb44c874588913ed640a119b5e9399851ccbc424bd1e3ac25" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string154 = "f3fa1708ff76cf83f28c5967402f55c2e7b744275932f8e457ed4f53e213bd66" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string155 = "f4f0162579e4bc334ab0f4be1ac02fc7f459243e6b9427f68a9b18c38af48210" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string156 = "f606ecc982d3bcbf1ec4651a183d542891fc325f9099ba0e802aa6926abef724" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string157 = "f67a3d9c0c161cb273819ff6fe64f8aa45195590d8f46e7dd91433a461c4dba3" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string158 = "f74f648e1f204b440412e63a970d6ab69fc5e09923a7eda0488fc45d7edc147e" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string159 = "f89c94c0952008e38b1da6f73fb2b2802421673db7e57354e6cd5755a47553a7" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string160 = "f9225d9986c9dc0cf328641af9c66eefc10f40c1a344d26bd847a219c88605a5" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string161 = "faeb33a916c28f17388206689e255337bd5719690602b2b18c6577fdf036f9e4" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string162 = "faf479fbf0d01c79ff3972881840913b6c18a24f2b51e7e29050c45760f0ea21" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string163 = "fec02364227841d1e69c43296245b8606dbabb94096ff43088d7ece41f003aac" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string164 = "ffe12c22c2fca0229ce7fd8e7a5953a3df57b32a1c152ad5a104aacbba874a00" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string165 = "ionuttbara/windows-defender-remover" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string166 = "is needed to run the DefenderRemover " nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string167 = /RemovalofAnti\-PhishingServices\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string168 = /RemovalofWindowsDefenderAntivirus\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string169 = /Remove_SecurityComp\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string170 = /RemoveDefenderTasks\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string171 = /RemoverofDefenderContextMenu\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string172 = /RemoveSecHealthApp\.ps1/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string173 = /RemoveSecurityandMaintenance\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string174 = /RemoveShellAssociation\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string175 = /RemoveSignatureUpdates\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string176 = /RemoveWindowsDefenderFirewallRules\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string177 = /RemoveWindowsWebThreat\.reg/ nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string178 = "version %defenderremoverver%" nocase ascii wide
        // Description: hacktool used to remove Windows Defender
        // Reference: https://github.com/ionuttbara/windows-defender-remover
        $string179 = /windows\-defender\-remover\-main\.zip/ nocase ascii wide

    condition:
        any of them
}
