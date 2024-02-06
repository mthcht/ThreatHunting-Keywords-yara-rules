rule godoh
{
    meta:
        description = "Detection patterns for the tool 'godoh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "godoh"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string1 = /\/cmd\/c2\.go/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string2 = /\/goDoH\.git/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string3 = /\/godoh\.git/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string4 = /\/godoh\// nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string5 = /\/goDoH\/releases/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string6 = /\/godoh\-master\.zip/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string7 = /\\godoh\\cmd\\/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string8 = /\\godoh\\dnsclient\\/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string9 = /\\godoh\\dnsserver/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string10 = /\\godoh\\lib\\/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string11 = /\\godoh\\protocol\\/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string12 = /11f51e1a8f1a630390533599cfbcb78133d680f6/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string13 = /2589213f0c51583dcbaacbe0005e5908/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string14 = /26953f6a9ae961392ed1484e9c7ace1211f5f962/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string15 = /27e71eebac244f803d825159fe3b1971c9bfb169/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string16 = /300875180931c7f9f62908e72395f992510eea9e/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string17 = /4045eef04cb934ac996942d0d51e80420b2ba985/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string18 = /438bf6db9eece197ef8d3e133a7e229086b5682d/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string19 = /4caedf29083d75d0d6687f56981fda77cce0849f/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string20 = /558df705dd4b6213c11e858b7c32960eaec39360/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string21 = /5e5a0618107570e45d2d2559d13658fb0e08f732/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string22 = /61254294a879235560c1bcf796ff256bc48d2d90/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string23 = /61c0af74e23b91ced41254e8d701482a157464d4/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string24 = /7423162b1a3b77b3cb5f76173204dd5983b683ae/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string25 = /86445d7ef450ddcb190f14c6f7fc8a1a33945c45/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string26 = /8fc21bc6c4a11583b4db44e3dad0980bdb5c7ace/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string27 = /911be80c0cbcc8c3bc351a3e60db0d7494858603/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string28 = /9bd15de627aa46533968e0f7fae19e8b855d0a40/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string29 = /A\sDNS\s\(over\-HTTPS\)\sC2/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string30 = /aacf6ed6e4b999a6338d5a025350ea5a/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string31 = /acda6b715fc3fdeed1f43c73e5467f5824093ac0/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string32 = /ae84192b77cec541a088d563dc5f20723123e096/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string33 = /b37eeeceb6addc2243bca9c408ee13554726772d/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string34 = /bb141fb92bcd492552d5d6c09fbf39f7f674eb49/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string35 = /bd976ca9268513e6cc4a58b85574f62b8a76cc92/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string36 = /cc9f09bbdb9277265fd71b7575b1fdda3bc2f946/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string37 = /d162d2e96da627fac5a93d5e6faf379aff092bbd/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string38 = /d67c342b9ffebd2350cb81d6dbbb35071246fb19/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string39 = /d9fd35586f323c9990b3da5c7c1f07c05ff88bc7/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string40 = /e4f33ee9ba4d86685f8df4a89e192a354139edcf/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string41 = /f27479a8728d9126cc055daeb5cddd01cabfa37d/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string42 = /f59e403b62053c785de7df979c5cb7b0f426cbeb/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string43 = /godoh\s\-/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string44 = /godoh\sagent/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string45 = /godoh\sc2/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string46 = /godoh\s\-\-domain/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string47 = /godoh\shelp/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string48 = /godoh\sreceive/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string49 = /godoh\ssend/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string50 = /godoh\stest\s\-\-/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string51 = /godoh\stest/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string52 = /godoh.{0,1000}\s\-\-agent\-name\s.{0,1000}\-\-poll\-time/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string53 = /godoh.{0,1000}\s\-\-domain\s.{0,1000}\sc2/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string54 = /godoh.{0,1000}\s\-\-domain\s.{0,1000}\sreceive/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string55 = /godoh.{0,1000}\s\-\-domain\s.{0,1000}send\s\-\-file\s/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string56 = /godoh\-darwin64/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string57 = /godoh\-darwin64/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string58 = /godoh\-linux64/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string59 = /godoh\-linux64/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string60 = /godoh\-windows32\./ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string61 = /godoh\-windows32\.exe/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string62 = /godoh\-windows64\./ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string63 = /godoh\-windows64\.exe/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string64 = /https\:\/\/dns\.blokada\.org\/dns\-query/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string65 = /https\:\/\/dns10\.quad9\.net\:5053\/dns\-query/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string66 = /https\:\/\/github\.com\/curl\/curl\/wiki\/DNS\-over\-HTTPS/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string67 = /Receive\sa\sfile\svia\sDoH/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string68 = /Send\sa\sfile\svia\sDoH\./ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string69 = /sensepost\/goDoH/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string70 = /sensepost\/godoh/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string71 = /Starts\sthe\sgodoh\sC2\sserver/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string72 = /Starts\sthe\sgodoh\sC2\sserver/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string73 = /Tests\scommunications\sto\sall\sof\sthe\sknown\sDNS\-over\-HTTPS\scommunications\sproviders/ nocase ascii wide

    condition:
        any of them
}
