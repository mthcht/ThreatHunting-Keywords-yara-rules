rule pyrdp
{
    meta:
        description = "Detection patterns for the tool 'pyrdp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pyrdp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string1 = /\s\-\-nla\-redirection\-host\s.{0,1000}\s\-\-nla\-redirection\-port\s/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string2 = /\spyrdp\.mitm\./ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string3 = /\/AttackerMITM\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string4 = /\/ClipboardMITM\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string5 = /\/FastPathMITM\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string6 = /\/FileCrawlerMITM\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string7 = /\/home\/pyrdp\// nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string8 = /\/MITMRecorder\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string9 = /\/pyrdp\.git/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string10 = /\/pyrdp\.git/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string11 = /\/pyrdp\:latest/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string12 = /\/pyrdp_mitm\-/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string13 = /\/RDPMITM\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string14 = /\/rdp\-sniffer\.cap/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string15 = /\/SlowPathMITM\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string16 = /\/TCPMITM\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string17 = /\\AttackerMITM\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string18 = /\\ClipboardMITM\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string19 = /\\FastPathMITM\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string20 = /\\FileCrawlerMITM\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string21 = /\\MITMRecorder\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string22 = /\\pyrdp_plugin\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string23 = /\\RDPMITM\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string24 = /\\SlowPathMITM\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string25 = /\\TCPMITM\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string26 = /\\test_mitm_initialization\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string27 = /03bf355ada5fc5ff405e694df967e893d9db590653fa89c1be81350aceda72d9/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string28 = /0434b626258ae9832074c8693921e3252a1804e506e555b5053f0793fc9e6f09/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string29 = /07e797c5274603d550b84df6cd3300d7ce9dc9903237b7f11b66821655712956/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string30 = /07fd00d4ecb5a197dec04d8ea359227ec5b6616f67034dda1f5da8824df91cac/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string31 = /083c3acddf8e359225bdb42167294f87b16095eafe686dcfab41cd0e2d5e7ebf/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string32 = /0e3e7f92c7f8f10535a6a15079813e2b8a3f5e4cfc00a275d2a2e917539306d2/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string33 = /0ed8c3f90c77356f7d02574491f66586b96552efd0b6ef53d7de263893061bc5/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string34 = /111c72f8a97ce4e1bdfcf1815c4ec433618e7a6c1c73c567f1059d2175357c42/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string35 = /1328197e04ea25df954765cb6b7cd7a2a13bae3ffdd71c4e60a8a627508efda6/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string36 = /148a719060fcc5ed37c33027cd39e320ca7fdd113500d5ea63128b8c506d86bc/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string37 = /176711b9ba9b2e01fbd5ad4ad2770d82985caffc02f70d4aa7585fe44508fbd3/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string38 = /198a1a3d69ff345e90ee64c3b437c7face55537cbe18b40506d54f5c489bca68/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string39 = /1d3d87c94b03ba803b6af7fd142dd874aa26a2754aa6874b7c498d26ff6152e2/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string40 = /2125a6fdc68bbe336f3a1e71163380872ee797a748ae6a30dfe282c984646bcc/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string41 = /238214970b5fba5a7eab8d9fb50c79da888018ff2a63ad49d1114b8d478d559a/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string42 = /2476217e429b83ee5584cd469558a374e054a604929150314e671f140f5d55c8/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string43 = /28dd3615a9603eb17b828c09dbc2d7eb66ff096389c76b383076bda48ee146b2/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string44 = /292a7cd013a3291a7d1b0004c6da3ce863dcca353f77935b385e97649eac39d4/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string45 = /29a507e37ad10b3ed522b8a524fa2d8f99978f42f16bffb9872d855c53345ca9/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string46 = /2a0d512c0fbacaa2029dd11e588342e80bd47927a0fa7535c75714aed2404232/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string47 = /2aa583cf99e14b810027715517aa588c0261a8df80fcb8018c29d2ff5d8777f3/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string48 = /2cd529d03729e9f59323391f57762c0952c6bd800ef46fd58855775bad7e7acc/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string49 = /2d6283f2487ebd6093546fc46eac56e5ce592c9ad5bfa70ee785ac0192a71d03/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string50 = /2e8d79c2cc6104f5c4a27104b0de6d09f5d204d56c81f389bdd9ca8e35cce298/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string51 = /310d3ef0d6aedac04e40ec62115f8d44d06a57a058030cc1a99e2d6665187eb7/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string52 = /33c0ff5f78f090a28573baf8ad735c82728c289a7ddf80df5bbf90c794cd7f39/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string53 = /37ffc17e18e52704214b980c56fad5a3ee6c9941905a9b76a3c914d82f3d1a61/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string54 = /3930e87199b44252705c1114f728e3ca38e6439a7279ef8d7fd33fa9869b9b43/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string55 = /39537a85f0b719915f068289d3e6da72899861afcdb3ca5d7a78de505629ac8d/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string56 = /3da905463c66fecfe69d608e98c6cd1defda607d176a73f2b38192a79db3fc65/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string57 = /3ed6aa523846443c89fc204956bf871d327a14862e0a65dad6e6f4854937e099/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string58 = /4420ccad05518f31e8960f7af1dd0d50e34331ff19fc618511cf91ac557e2f3f/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string59 = /446c06c2d90d1afb23e58a0185087888a5225a6d16aa3949648a80c47e2430ce/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string60 = /4551550ffe88fdd08a358197d4e3da663bca78d6896484bbf081cb70b794f27b/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string61 = /46f917a6a3de5d2b29fd77a842015ac27e6e3ba2faa92395c27666b2721dcaa0/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string62 = /47fcecd53c11bc648d564c02592617a6ce400d59c94167eefc9a5f7d86cb645c/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string63 = /4c1c75f1a66eab31836ec53726fc47591a534688e79a5818ef63c1682de88cd5/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string64 = /52652b9d89a6fd0617b8f0f60b0abef4a972fc0b7f1f861e5be029f7b2eb4dce/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string65 = /533c13619981d1cc6c9780668aec4a86fc179a7a6ddf01b6b5d3ae7edd993572/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string66 = /54b2757e66ac5e8173d2af618fed10afc4c3b28d02c6324847c24d8bb17c8a45/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string67 = /55652291077fbb6c957ea42379d965892e29695a85ce00844c7b1c83971ac1e6/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string68 = /57dbbf5283ae35badf6a08c683f767a44c9efdde9623c0fa6429d8672c97a18e/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string69 = /596f3d75d96f68ee6e91c6c5ec4180b6277b6f067e6fe233193c2f75dc554e8b/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string70 = /5d61397acd2c3b39da7f48673ce25690db669c68d538487cdf79ecc8b56f039d/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string71 = /60dbd3f5c48a846c11f88bdc3d30de5f734edec91b1d18058223a50961195646/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string72 = /60f9d7ae7082d1c524ad8e38377662d82c6b32d3f5b9c5256df4d6e3aa74865e/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string73 = /6357479243a64e0edc18f138b2f1ccce22e4396db9ecf4740b71f6185ea055f1/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string74 = /638f7368dfceb394d7ad1c927ce5399386833816bd099ae41db5a249c3ff8362/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string75 = /67606cb8ee6060aabae4dc8f24fad06d058363de920ab03511168840fc96111f/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string76 = /6b3d229a02f91fbac23a4385a1b8ca8fe851c9c99c94341dfc5fda41cecc1283/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string77 = /6b4a7999ab5fa112e69ea99a01bcf41a23c8a01780f96eb1647fa98b80694113/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string78 = /71146194df27fa843b2d1e8e5bbc924b19bf61f6d89d3ac76aaf8270c443fe78/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string79 = /72b675d40bc3c796892caef0581456f9a489e7195527f67ea5b819dac372e89a/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string80 = /772a8b19e2abd21dc6f10dc1ac4ff07e52e8f242716c1308e14a1e9fb81e7cd7/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string81 = /7a2fb0b27e7c44f2a37ad254df79b3677b010d34bf6421281a2a37c1088d613f/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string82 = /7afe27385edf41f8365eed21b7f34467b574f2cb91f618ddcae75024f6403c41/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string83 = /7d2a12270debccf539db741714c724d3bf88d9814e3056533ba2c712c71b0ef3/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string84 = /857d1a53ab8df17acd27c5a26a77cdf070b2cd6e78bcbf011eef3c81dd5cd9ae/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string85 = /874dbda99983730fafd8054b29996e692cfe12c4230cb97d3b53e5db4df4238c/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string86 = /875c428604faaa6f393b263aef783d9cd535b57135d668d949014052132e3c8b/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string87 = /89d3f128432dd85a62c1f1c394dc8a0397ba23c5a193449dabcae0d1f84d3b18/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string88 = /8a92acfe944c48f247b50ea26cb82f367e668959c115739c025d1ad4ca59a27a/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string89 = /8cb1ea0098cf975a1ad6d61b2a387f8acf09ef8576ea836f838aa6ac9c0fb0fb/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string90 = /8cd0ff4a46caae1508aaa14d69ac3393f05d2e58a1fd94d8c8b45a3ed6a6a474/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string91 = /8d0cbb7280381d6847295ae41a30dd19afb7a27141b95918561e52dbcc458182/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string92 = /8f6fd0bc95fcbefdfa01a3f7e809914696bc1285a7f7bc39c3bbd1d2314b8299/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string93 = /9183fb7b9d4dc2bae17ce77d1069811f767fe88d17944c9cb81120af0c239faf/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string94 = /920e37529214d87fb835861d8c539e5c70d9d98fb0f48ad097760f298aee30d3/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string95 = /9372fc352f24f6f58fe28bd7d0ff4cdc3a384275c7ddd6f76c4fa40eea0a94b2/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string96 = /989080753be26eaa2b93d3a01bd4296874162f06d126f78be96749fb95c66aef/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string97 = /9ea9995496c329267d7bfba8f2061b6df43d5db255bc103b14730042e782e5cf/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string98 = /a014358676f18ddbcc1e281a2d21d3fa817bed4c08ad221db34638460d2a24f4/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string99 = /a1dcb84528551c983c11159b99c9d9ba1d3aa75659d9a16a4ca8204a6ada397d/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string100 = /a314666c9d3b9d80540bb50378fe104b1c509fa239bc80567f26492f76c526b0/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string101 = /a324c19c7df7c2c63f4fc17bc8e1554e4261a27c18cd68c47cc08602f480d60f/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string102 = /a3adf686eebbb786431c1df3c1988eb013877596d162ed642fb7e52e285e7296/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string103 = /a4284269b4058b687af441673ccc1a09dbd013d3dc54546848837ed44e0023af/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string104 = /a856cacd5a888686b543aaff5e4ca96d47872e3f59ef4b68701a035d5d35486c/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string105 = /a8eb0e74d8b13b7467faafe2bda9b62634c237322ce951c3655578f3331a44e0/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string106 = /a9307f3ece06735d45dbf3af3f84c5787f7afa194927dd3322a744b8f65ee058/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string107 = /a98134e477c7bed393de4421eba7773ccce4cbe9bba6ab00fe260338691c352f/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string108 = /ab7aa0e4c923f767e50914842239578d36723656befca7bec7d40926bf79c3c3/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string109 = /ab7d1d288bd6635e9fc098fb1a1b0dee7956ddd5b61b3a8444f0e8c8198e598a/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string110 = /ae2342b247b29e9e790ef5ca3bff74f49167b54a0c846321fb5e7e24bf892d74/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string111 = /b32776836ec9757de71ab8306f38ba4b2d3e556c5bf7036221c2153619c4dafc/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string112 = /b7bb45d67e4db4c923cf5e62d0fc8c9ae23abfe214c8daa730d343b0d9205837/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string113 = /b7c7c4caafe06600e68c48eed104ea895a933df2076198e27707af00996c336f/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string114 = /bba2c964972ac62ae9f9a2e0ee0046fa046dff0cd53183ca2169e1659c234e98/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string115 = /be28f0c338095b629bfd563abd38c472c6b88618c3647a97c79f6c78cf620e15/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string116 = /bfe6da625226d373022fe4c5f88ccfdbae6c102207b5a44d6aff3c5aed20a56d/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string117 = /c13e7029b5bcb568a5d6fd9a1042e6a2599ac8c5795db5348124a39663368094/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string118 = /c33226c3905c340a634103a8868f968efc84ec2c8bf441df2713305979c3b0c6/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string119 = /c6ffad5c09f5fb6fe7241d3fe9c9cd968ceea15e483a180ac45bd0b4e15d7bcd/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string120 = /c87bec6a236d81bed01df7c7e576308bf421d4cd3afa826a3f439a422a888fb9/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string121 = /c9448628b8a4a715f780bf821eab6e39962a774ecdcf808628ea6ef952372722/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string122 = /c97e3b0e4180217fe46b36d70163c750a40ed76d402ca6c1784e3d8e6c3b22b0/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string123 = /cacfd6b17986292835f2cfa05562c0565a923a246677fc6eed01d426ba74300e/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string124 = /cb21e55fb1b580820aaf8090eae7e49cd59360e91456ab85a74828107e1dedde/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string125 = /ce26cac7b0d52a3922cc05a777bb83025430a6a5d31104840a0099d7bd0cb2f4/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string126 = /ceffb6a2cd944a1309ee3b88992ea04e456f17bc2234b861bf1ed43e51a3e973/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string127 = /cf1d4595c7a03ce084a85f1545ba3593dd396eb88049c6d5c87efaa594e41c7f/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string128 = /d2b0e14706fc0c11bdc7d1b35463150bf11c12dbf63045d79c361f23abde33dc/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string129 = /d39ee3711191ba35873ecaf10a0fec4d1bc80bc31a6718e2954f6f4400075d82/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string130 = /d9e138fbb6a18ba5a8f9405a45144f86211187609b158f862eba7a942360b3a1/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string131 = /da6c929d77beb9a7cdb968a22a9e39343f27f0ac11672e11adaf3c773bd32c95/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string132 = /de569a85963dfe8966a51f5e5fdd9ecc9cbc30721fc2d624c4c29c6cf6d12adf/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string133 = /debd82bfe5eaf80dfb9d254962df14431f231cde2c09b8efeeed73e4f263cd98/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string134 = /e2ea75cda1cbe2d628b20a93a49904f17d158866a644ff262d3c59731418c9a9/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string135 = /ecfb9ac1dd1fec043188b3c66c6fbc54c824c9de99e964abfc08836e9877701b/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string136 = /ee29b50f82ac78854af1e014fe9986a9699f98683ca798092f6b51282c08d640/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string137 = /ee2b096fee2d9337ce5b2e1506ffdae090833eefc634b73f22046679de392f05/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string138 = /eec5232b43748fc0c8a86e2b3e7b921e88b9aa0275a0ad3b4f719f8e468b1f95/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string139 = /f57841b1ef43a21bf127babaf02f391fa0d174b618ccd10b7326b4d83089d78a/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string140 = /f58eea2ad17ebbb4245ab1fa29aad1afcd8569ce4c460590438b2e88a16a5529/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string141 = /f844a6b49da27594cf1733faeebac268c7c790c48f8c5bb89dfc1bc7c20d1e76/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string142 = /f888e9662215d81edb90112d66c462e3ba47b9007efe21492e9c8d76909836c5/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string143 = /ff21d3231fe5e5c81f8640a0448236555e0730c58e4aec21c8004c6aa71e4eb4/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string144 = /gosecure\/pyrdp/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string145 = /GoSecure\/pyrdp/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string146 = /pyrdp\.core\.mitm/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string147 = /pyrdp\.enum\.rdp/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string148 = /pyrdp\.logging\.log/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string149 = /pyrdp\.parser\.rdp/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string150 = /pyrdp_output\s\-/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string151 = /pyrdp_scapy\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string152 = /pyrdp\-clonecert\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string153 = /pyrdp\-convert\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string154 = /pyrdp\-mitm\s/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string155 = /pyrdp\-mitm\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string156 = /pyrdp\-player\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string157 = /RDPReplayer\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string158 = /test_mitm_initialization\.py/ nocase ascii wide

    condition:
        any of them
}
