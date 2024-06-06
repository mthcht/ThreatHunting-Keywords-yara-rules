rule rotateproxy
{
    meta:
        description = "Detection patterns for the tool 'rotateproxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rotateproxy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string1 = /\srotateproxy\s/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string2 = /\srotateproxy\.service/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string3 = /\.\/rotateproxy/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string4 = /\/bin\/rotateproxy/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string5 = /\/rotateproxy\.exe/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string6 = /\/rotateproxy\.git/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string7 = /\/rotateproxy\.service/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string8 = /\/rotateproxy\/releases\// nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string9 = /\/rotateproxy_.{0,1000}\.zip/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string10 = /\/rotateproxy\-darwin\-/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string11 = /\/rotateproxy\-linux/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string12 = /\/rotateproxy\-windows/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string13 = /\\rotateproxy\.exe/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string14 = /\\rotateproxy\.service/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string15 = /\\rotateproxy_.{0,1000}\.zip/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string16 = /\\rotateproxy\-windows/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string17 = /00015f0ed60527ea65a612a07f73a3b8e3367eac36a94a21a73667e4a83a930b/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string18 = /039502d988c5665676f38e37c9ef27969203e4d552bd1f1c732c0c0f4c093016/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string19 = /05dbe6775382b2e504716c2d1e1631eee298950cf4503072599d92cf07746190/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string20 = /081a942df7cb4e74d01caf742178772aa5ec00905a6e546c5d80b5a495612bdf/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string21 = /0b4559dcd86d86e5c0cd54f123fdcf2d7011472a1b134aeb3ed14782a4578111/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string22 = /0b5aa7a7f74d9fb5251bbff02e7ac43a3cf47be0a2f02d5a208ebd37032d12cf/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string23 = /0b76a0444f290530c45bb0e0dda192ef0e316e5e76133e34be07b383880c959c/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string24 = /0x727team\@gmail\.com/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string25 = /13de5a5579354f61ec2220bdc9f6bf0468243a850ab99a56bbdf2549145d30f6/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string26 = /155ae1264e89d69b716194c767d7b05e48588c30559be534b056a6a837ab998b/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string27 = /1563ac6f8ae849b7ab2da0a5a154f29449cfd13917b9a13bc6ebab004445075d/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string28 = /17c82e0a4054f13739f057fbfa1dabfaf6ca373edc46e345d8e5553dfff3dd7d/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string29 = /19e7a5fd08ffa93823b623f349a5922b026253d535381ced0ab0e107d1a67069/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string30 = /21fd3f69a45a2eeb1354cfb8e4b44c6d07cd30bf91698ac5831fbb13846f3f56/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string31 = /2448bea950b409f78ec4ef893351cb860d45dde31736bb771f34adaa44e6344f/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string32 = /257669b9f912f7e9176cc50844b641c13f37428237cdd4336e497e148158d5ff/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string33 = /2bd985502d207cb415eab56024e67a963e2b6c07d681f8c9ffb173fd5244cf33/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string34 = /2d578c9039ded100955310b7c6cc6a8eeb447cbabe86a7baa3b2c873795f26f8/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string35 = /2eeed72ee86a276b08351436a84e2d3c3e8ec3eda25f8207b9c5878bb7541764/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string36 = /30953a500fc7c834d7796b370c290d978e11a090dc28a62e5753467f1d00da7c/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string37 = /316511d5905a2222abfe317a2fb937588825fe29231c5b122ab790966c3a36bc/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string38 = /354f944df24458e6113663bf2886bcd902304e0c2852b4447bb386361ca3ef86/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string39 = /3ab344b38cb1d65babee1a52210280c415e6839642bbf7e7b9c4cc53d5b72f04/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string40 = /3ae2ec1c3a9cb120b6c296aed13dfc8973449c74e8a93ed0de0f3b85ef8990d3/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string41 = /3c5d50fa8f74bb4bf13e8b086490bc1d520b0a03b56e8d2b2f3ef65bbab2486a/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string42 = /3e829ec96d65a4bc7c962b997c0363ac690ee3206a413980cc7bb8d300c8a3bc/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string43 = /3f0ff74a551ec7b47b6509a6ebf6e6ef795c7b770cc3545e2fb8296a5ce4dc05/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string44 = /3f460ca63fd331cff0f5f7e7947513822b5a9fdf43ad10e551fd785b2de0adf3/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string45 = /40e7cf7955a9a2beedf5d284529036b04c65650f81e81776d8c63713e86b9ca2/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string46 = /436a88ff9bedb6b4264d64e28be4a4c1b41e125bfa5fdab941c6d045d9a4e77e/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string47 = /449a2fbf36afadf80c8655c09acc1418d286106f9ffe9422c0879861c7a70e58/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string48 = /47a825e8e986071566b2bd72e956bc88f422348ebe17b4e142e7c6a1a1eb4a1f/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string49 = /48b7e423f61b11878891dd7005b2b2ba88f997d4501c405fb9c69f932499ee74/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string50 = /48bbbde23d4a33619295aedd90361d246d1edf1082ba361a54b84b706304ef1e/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string51 = /48be356e1719a3dc5c38db4463716ca90a21530266e657b1775b67c7ac25f922/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string52 = /4b0ff1bd0004ab3d3ec7fe99d489246671adf95aaaf8750cb413bb77acfbfc18/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string53 = /4dc4fec23df1e9a1fcd37f4edf731466f14eefa9eded63a3387ee14adf70e104/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string54 = /57d4776f876ce736a4fc01476dfc2bb04672edbd7a5f52886a3b11528cfc23fb/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string55 = /5953a5d8fda1ee62fad196cafa1183abf11bb5555b9b534756e98a0314411513/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string56 = /5a0c1ccb6b02b2bfa1d84be0b8055274b884f0d58447b5b3eaf19d9c5197c19e/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string57 = /5a70e9ca5bcdc934d1451843186cbd70a5869e3d1694a5a81a177fcc5ca37d05/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string58 = /5d9b00a706436f93d927799d4dff0f1b53af9a10bf3bfe0c7918595783f3ddf6/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string59 = /63bf4fdc657ca1599e0f4b6657bf656a5c9f9f3eeb7af957e511707436109835/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string60 = /64ac445fc926e54e4083cc474a92414c76ef1e22cc002bf52efd3db5594cb76d/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string61 = /6500d2030465216b60c086fbbbb4b52ec043473c802edf71d9b8277ee4b52efe/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string62 = /654685d39d4c33cb74a990013bdf18883d774c609a155a6461bd76e93167792c/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string63 = /65cf10c4827342b6b8a8f2d5d094e300e41d4a3924efb8865e633d6be7fac3e6/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string64 = /694eb99d38f28ec564d480cdd05e3b6e703b2c0d592276322e7a74602145a5c1/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string65 = /69d9dc8b265c039ff9a5677cbe5300fce13f17810d2dcc69a3705962adcb5015/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string66 = /6ac46beb56b053bac9e406bc16131669c93c8f578a3cdc467821ed07c03e596a/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string67 = /6c2ceb31348ef2780f96483fc744807651cc3a72d1dceb808ca24bc36bc08bec/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string68 = /714f969a0a24c346dda4c22eca5536e3d86f7137e64388af7c54e3b11db499ac/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string69 = /71eb55cc0de1ddeff8b130ab5744a895f30fbc1b58b4a6d12741311415234ad3/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string70 = /7270493d60dcc3d13246558e2d6784a4ff5c45d8d6caaa255a3692ea1640c191/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string71 = /73273aa4152acec4126a3cb03e1b5afb4198e24bf3e71d426c3b14fc3dc066db/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string72 = /750de413f15ccf2befe7b1b298a3e4dcd7d226b7eb16ff4803dc4593d1faa320/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string73 = /755dfa63130b4daa2098ee3253b0532cf2bd5307e9036fa3cec74f9755b79601/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string74 = /76b716279c94bd8e32e1e360ddf0994a74ad51bc6fb094a41f11163aef901116/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string75 = /7870be97747b352f74adf2c6dc96d647240b984517155f46565ce00307df0248/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string76 = /79efd1cb38bfa9ea0c22059d17bc11498bf0f181d5dba1726fa526a500865ec8/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string77 = /7b97e3bd5491fc4a6c4a29b77dd36682e1bc7969a1ed8cb9abd4c1d4819eb00e/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string78 = /7dfb613a59e09dd5f01a83c3980fc661ccfc2875c2091165c54e5989954907cc/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string79 = /80f32d3706de3583f3228e9dd2d53375868308bfba3add3ae2637adba6fa392b/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string80 = /82855507e35b8f9645bd13b04b74a9cbb02afe3815d37ee7f4837aa7e97eeb10/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string81 = /83b3b581686f3920fed7238e4d5ccaaf47226447a8894189fc3cd4e5a99a5d96/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string82 = /84ba0c573d8037b6ffefaecf7aee506624382ade184e884e3c03dae8c1f33317/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string83 = /86493698c14d838bdef05d96811391a6dc29b9066ee5183f3d1924eff21bda56/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string84 = /870816a0e737187219a0d5034b0dc9d492763b27bff3443fb291bf226a83cc33/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string85 = /87ea7ed313b723b21d126d3a9ffa5daa2a9713853f1fba9274044b78fac9f40f/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string86 = /87ea7ed313b723b21d126d3a9ffa5daa2a9713853f1fba9274044b78fac9f40f/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string87 = /8898af517b30c917a82e087530e829ec5d46a5dd43759fb66202e3945a380aa5/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string88 = /93317a49d4e0065e7bfa8c751e5f5d86087ef4c09c4f5d883dd9d9a69871f95d/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string89 = /94b33b49ee9fd258173cdc1a31c1f330403d6dc78540bf7258e8c9b6763334f8/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string90 = /969402c4db5ce5946e2fb9242385a5e21328780ae6848f133172b00506706263/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string91 = /9e3c27168bdaa45fe127ba530d5f5bfbec067088fe92d02b78342a0e66dba5c0/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string92 = /a1f8ecfc8b1e67d081057d151ae638191b5b39f929c1f0447af69e23476bca1c/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string93 = /a28d627deaf54fdabd986ea28160bff5c469f53dc5be72ddd58b3bff89ab1e89/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string94 = /a7e9bf156061f6312c826da68a6a0fa9ef025cde57808bec004065ff2fc108db/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string95 = /ad89fdf30b1ffef5cdf285079f018969976d37a143e19bce810c6b234a8f58c0/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string96 = /ad8f8790854a70fc8a3f5d53931d0e56a2ff0f037cf781fccfabcb4334d817be/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string97 = /akkuman\/rotateproxy/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string98 = /b1f614b7eb188e8b7d47f08e333e05704aae24220409ab4e7e7b9fc03d339fdc/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string99 = /b4ed9c347e748f0fac2c3e75852373c08fdde68ec741c45109e8afd7c3381f0d/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string100 = /b6e95607f7434e41adcaa98e42af0a47571c7af29ce0418aa582658f6f539c6e/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string101 = /b7a9d9eff63ab4a330888d498d954e78cdc19b44435f26f6914aa4b2bbe86bbc/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string102 = /b7fb827ab82836232bdf3a6be19a1ebd3d5194dbff0b922b0ae39f8562c9822f/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string103 = /b990e7cba87af7e6a61a0c326047e99c0750313e6c9bec82ab4b6e2ff757d8e3/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string104 = /bb01642e30001ee637c9d4fc341484c06eaba67e8ce00b52dc6faf71b2daecfc/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string105 = /bc039376443ab3eebc8b1f876e47c19fc2cd74a9417f7c8cb75d5b0c090f87d7/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string106 = /bc6fbafaafa92286c70e56a47a47281e3621dc6a0e606540e9e2ba34db51e21c/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string107 = /bf4680186f616fbb0bf0a3cb01f520d8bca46d6100218ebb26de90b1ee3adaff/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string108 = /bf47e463172e963f10b9c7e29995ef10b833b6d5cc0fd5a63bae1bd8d69410a1/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string109 = /c2dc48ba4a9ef1c03de0fe5d6df430df3a2d61792d2220d321702adcdc582162/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string110 = /c369ef94296e539c96f7a8305587d3098f0491dcdcb0cd6d006e7e2df318d19a/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string111 = /c4e091bf77e1eda6f74951893238a2d68b61d530ad71ae993f21576ef80b6903/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string112 = /c4eac73762f7e920030de4e0de677fd6c87372ec59fffcb636996d6ad86358d9/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string113 = /c861d54834fecee5b581950037912e302f14fb706c732929d7cf3e5a954fdbe1/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string114 = /c995ae7e3e3ee04173a5ff56b676ed74057cbdc9fec4466a4402a42c1d56e060/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string115 = /cb10b5bb6fd0d22f1388cd1864af49f224b7caec1cb56145b225b6035da73428/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string116 = /cb9447135d98011ed452d9b69d6b88f732ce08e2481b1c2f78b4bdd36d090bb2/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string117 = /cc65a1b922258d72afbe7391a32a58cecfddb9ee4be41de53cd8a52b9b67b277/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string118 = /d14b86691ed977fd4c29e0c98bac637bffc86c46e83768f73432eb26def0bcaa/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string119 = /d1b397d550d1f9921048c02b3401aeeaa070c99e5c369738834e01a6100c5396/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string120 = /d1e05f79d0b0643b230fbbde69607d9ce4f20b8f19a8c47a91bf8beeb50ea147/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string121 = /d44971afba15d74da67705ba5d44c7810be3b40baa11c25def44db606e6c8dfd/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string122 = /d57d2b2a2a345eaef9c6b06bb8cfb2ce2578b775cdc5deacfcada080db784f33/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string123 = /d7cd7a952aab71b1a1bb8ae63ce23776e5b4cdd57a1ff1ab747e9fdf0e4a548b/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string124 = /d8043ec0bd5263618118ce4f327126c9413fa5f041426117adc0d15e4a168144/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string125 = /d861f9c6114dd6d6e8227ec4fbb0f76318a36a384842eb76b5c3131a35b5c513/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string126 = /d92aeb275dc177206baa4ac355fa43c13bd53d309247b61a7fa563a062f15ecd/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string127 = /dc07fa75e50a2b71b6e6163c0052fbeef8aa20896af6346a6646692d09bcc06b/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string128 = /dc56b9ac51cdacc0157d4180275cefb938e8476356a46b1faed2fddfb5d1907d/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string129 = /dd789bbc91be5932fc0647ff4c88c3932ed9ccf2114265985c11481b6f79d848/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string130 = /df35838ff39fcb2ec8c8783b4485abe8b7cd805bad795caf730e6886e48655a1/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string131 = /e04c023e1ff561f7bdfaef366050533bf3f6e0a06675112911403fc5d3fafb71/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string132 = /e11a3ad89cc8150c1ce7367b3360c717c6b39feb61986a37385af368df2083f9/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string133 = /e62043f8389effbe26300cc7cd1d9af3b25d6efc1eb0d604d837f58a89e485ad/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string134 = /e732db692f0686f1a3118614deda581f692219020f73e9728c9c9ead0ae50836/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string135 = /eaf0b65b09feded70f455b4fff79bc1fd2009b927849ad4ba63228d79fc90d4e/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string136 = /eaf13ef05abfd1faa71d5ce0aa0b19664bdc32d05dea7836ad6d9bc0b2ff1694/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string137 = /ebfbe1788f944eda7614d311a9b6ca197a6d595910bf19e8f8dcfe7d92e77215/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string138 = /f213e2033269abce384e1f85c7ab9730d3527f6b1258322e8d3ad17e4e1f6498/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string139 = /f3a81e60a02caea629cba10af9f8bf769ca6d6e2d45d6228c30f3b544e1f7f09/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string140 = /f3f1e7ecb0fbc06203f6300861cca295e2de0a1a2f636e4d6dcc2ac651f40acf/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string141 = /f515b31a54f823dfcef50ef4c3dbcc64e6062f5c5dc7f98b20b30c7cc0a5f3ff/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string142 = /f8749220e3a914ff2323237dd52e8ec9fd2634be7b0b4266ef57872ffe29f845/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string143 = /fb5490f0675eb7ff5a4f76341e77a1bec6b77d3546c9a779676285d0c2d3255c/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string144 = /fd781d2a9ae86e8131b370be6b96807f532b41f093d8d85f906e9c2ece2f6c64/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string145 = /fd7bbbf6cbc5d86a8c6ec8caa40aef39961bf9b3d15b515dbcd2469bf15e390b/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string146 = /rotateproxy\.exe\s/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string147 = /rotateproxy\.Info\(/ nocase ascii wide
        // Description: A tool that uses fofa to search for socks5 open proxies and perform proxy pool rotation
        // Reference: https://github.com/akkuman/rotateproxy
        $string148 = /service\srotateproxy\s/ nocase ascii wide

    condition:
        any of them
}
