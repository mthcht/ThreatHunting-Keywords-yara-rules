rule sish
{
    meta:
        description = "Detection patterns for the tool 'sish' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sish"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string1 = /\ssish\/deploy\s/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string2 = /\/_sish\/api\/clients/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string3 = /\/_sish\/console/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string4 = /\/cmd\/sish\.go/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string5 = /\/sish\.git/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string6 = /\/sish\/keys/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string7 = /\/sish\/pubkeys/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string8 = /\/sish\/releases\/download\// nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string9 = /\/sish\/ssl/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string10 = /\/sish\:latest/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string11 = /\/tmp\/sish\.log/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string12 = /086e623f343e09d81210818bf6d295f7eb12143e787d168973e16e29ea3a5942/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string13 = /08f1f067fdfc22fd7075eb73a2cdec749cf0052ccd0672954617b7e49eb1ca40/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string14 = /0f8802e2c560ffe447ecaf7e88b9a7a0ac526c8e13b382822f9b4eba16c744a2/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string15 = /186b93ae9e55f25fd6f409914f4e40ef85b92e0bec374fecd8ee293dfd362387/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string16 = /1d89fe4074ee5023c5c784c5e1020cb74eef55f476900db9ad1431f6d25bde22/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string17 = /1f814aab831b7854e120d10e1560fb755683ec282b1b740c2021f8d1de03bd3c/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string18 = /24882318e38e1e5778b7852196e754ead1af9de537ffd1dd3132467076dbda38/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string19 = /256f36a488c65848339cf910cdd4224dfc5a95b504e80ac46e003a7c8cd186f6/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string20 = /272175f4d98a6ab59e2f589ba7391fc36659b04d0f27f9cb6a300cf49dfd2016/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string21 = /2e944f0ec797e703db9def360969ee414dd733cac1ee7a3eac98d4131529668c/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string22 = /30a7e68f32b0c23d57cba6941e7f990fa147e47facb387085b26e3a16c37f0df/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string23 = /3f4a0c9d63796dc8d7d2bb3947edf3a2722c9e783e7c7fdfa7e13f2b43eafdc3/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string24 = /4146c24d1d9cfa4c6c019fe4a0bd22f7b5d18086b18b7a74a0965e16e7f94bef/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string25 = /4516398fb9263307b6632401b89e7a7bc979f6a8efa20492983e02cfd969de30/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string26 = /46ba3075010ce026f20aad133b871d4fec53b6d2972f736ee1a98a8d1bfb7ff9/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string27 = /4d1c4cce9f9eb46d0769639886125b3e378621cffddc61d802dfcc9de8018ebe/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string28 = /51a9f54d470e4132709b0587618053d9bc4657d524e22fbe5e861264da5a627d/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string29 = /5afdada4e30699db8a1903e8a57fb9b50783299b1a8606f145a56e15fa1a9521/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string30 = /69964da9297a1caaa4ba0c389d4ba8a97f14d9a58cdb1cb549525ffa9684529c/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string31 = /709b71707b611ad7d608eceaa3004435130cf7be89216cba2b4fdda77b3edcaa/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string32 = /7a8cf5bea004a74703bea87fabc76475cd2931856b9ad55dbaf7a3682f91c725/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string33 = /7cf1f7f7e6bf8b26c5c3a6c3b1a6b0316eaea86e0b2b39dc762d510b75f4709a/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string34 = /7ebe05cf3029272503d357300458d6bf36cde819120533d8ed84c1f9888dfc94/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string35 = /82ee96364fb2e2a1b96550fb3aff0e104b32eaaf1728c84a4a02a9a60b8cdb54/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string36 = /838e54cb93d57048d17204c85448b8ebcd4d1403cc3d8768ac02e702a64a6b28/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string37 = /87ae04b11731fe410b0e3bc87e6c99150dc9ba79bfcbd0ec4bf368930e6e2e7b/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string38 = /93eabc4b534f92a5532322bbcc461a04abbb0c32c3c4957c258fd77f451e3b52/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string39 = /94d8893a6c819e092afee3334fb7f2263704b30a1139fae76a67d52d4a4db801/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string40 = /95dd52dbd82039a3f19a2bf8b4517b188d27bec4907cfc7f1796b7fa09c68c28/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string41 = /9a3206e426e910fdc8b291763e15a9e52cb66c2d9b6437bb9ec54e3da97a60d0/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string42 = /a3db95daa151cb6ab640f368e1850108099cf94eee2bd2c3fd2789ee83bbcb71/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string43 = /a5ebda39b87ecf276f28faaccef680a07435906f81001ff69cbe6acefe345ca6/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string44 = /aa52afe3cfd41aa6bdc1601a8f5a8dc2f0cac8a7af2cc162bd569082a12aaefa/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string45 = /ab7c24fe58442c46ea47fe89b2b967d733d3a35e2f363af15ddfc82c6f680509/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string46 = /antoniomika\/sish/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string47 = /bb635b88ae16476a37144d24c8b0f898d619147d069091e9869de6db130db0df/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string48 = /bf40b50a1cb293cadf36aa0a2fe3309b682f08858a58bf6231042258e78a13dc/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string49 = /curl\shttps\:\/\/github\.com\/antoniomika\.key/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string50 = /docker\srun\s\-itd\s\-\-name\ssish/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string51 = /e3e70157c3a75c549870c5f2796a64c8de05c3d9f71fbcf76239f07875bff829/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string52 = /e4b3511a69efba9f59592c41a87992f7e23fb6ea45d18eca6ab19bbbb7bb6d6f/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string53 = /eb0d8e4273608c13b5957ac047f911442b3d55527e20097cd038e120f01df5ae/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string54 = /f3b1c8cf0abdaad743182c96258f5e88a8522004724a781596e6663565e5c456/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string55 = /ff800e89edecbd936169c78cbac4a524da8dd91c922c9909f5f6115bdc898716/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string56 = /hereiam\.tuns\.sh/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string57 = /https\:\/\/.{0,1000}\.tuns\.sh/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string58 = /https\:\/\/docs\.ssi\.sh\// nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string59 = /https\:\/\/pico\.sh\/tuns/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string60 = /https\:\/\/tuns\.sh/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string61 = /ssh\s\-p\s2222\s\-R\s.{0,1000}\:80\:localhost\:8080\stuns\.sh/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string62 = /ssh\s\-p\s2222\s\-R\s80\:localhost\:8080\stuns\.sh/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string63 = /ssh\s\-p\s2222\stuns\.sh/ nocase ascii wide
        // Description: An open source serveo/ngrok alternative. HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH
        // Reference: https://github.com/antoniomika/sish
        $string64 = /testing\.ssi\.sh/ nocase ascii wide

    condition:
        any of them
}
