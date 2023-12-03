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
        $string1 = /.{0,1000}\/cmd\/c2\.go.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string2 = /.{0,1000}\/goDoH\.git.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string3 = /.{0,1000}\/godoh\.git.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string4 = /.{0,1000}\/godoh\/.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string5 = /.{0,1000}\/goDoH\/releases.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string6 = /.{0,1000}\/godoh\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string7 = /.{0,1000}\\godoh\\cmd\\.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string8 = /.{0,1000}\\godoh\\dnsclient\\.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string9 = /.{0,1000}\\godoh\\dnsserver.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string10 = /.{0,1000}\\godoh\\lib\\.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string11 = /.{0,1000}\\godoh\\protocol\\.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string12 = /.{0,1000}11f51e1a8f1a630390533599cfbcb78133d680f6.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string13 = /.{0,1000}2589213f0c51583dcbaacbe0005e5908.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string14 = /.{0,1000}26953f6a9ae961392ed1484e9c7ace1211f5f962.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string15 = /.{0,1000}27e71eebac244f803d825159fe3b1971c9bfb169.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string16 = /.{0,1000}300875180931c7f9f62908e72395f992510eea9e.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string17 = /.{0,1000}4045eef04cb934ac996942d0d51e80420b2ba985.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string18 = /.{0,1000}438bf6db9eece197ef8d3e133a7e229086b5682d.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string19 = /.{0,1000}4caedf29083d75d0d6687f56981fda77cce0849f.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string20 = /.{0,1000}558df705dd4b6213c11e858b7c32960eaec39360.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string21 = /.{0,1000}5e5a0618107570e45d2d2559d13658fb0e08f732.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string22 = /.{0,1000}61254294a879235560c1bcf796ff256bc48d2d90.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string23 = /.{0,1000}61c0af74e23b91ced41254e8d701482a157464d4.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string24 = /.{0,1000}7423162b1a3b77b3cb5f76173204dd5983b683ae.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string25 = /.{0,1000}86445d7ef450ddcb190f14c6f7fc8a1a33945c45.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string26 = /.{0,1000}8fc21bc6c4a11583b4db44e3dad0980bdb5c7ace.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string27 = /.{0,1000}911be80c0cbcc8c3bc351a3e60db0d7494858603.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string28 = /.{0,1000}9bd15de627aa46533968e0f7fae19e8b855d0a40.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string29 = /.{0,1000}A\sDNS\s\(over\-HTTPS\)\sC2.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string30 = /.{0,1000}aacf6ed6e4b999a6338d5a025350ea5a.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string31 = /.{0,1000}acda6b715fc3fdeed1f43c73e5467f5824093ac0.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string32 = /.{0,1000}ae84192b77cec541a088d563dc5f20723123e096.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string33 = /.{0,1000}b37eeeceb6addc2243bca9c408ee13554726772d.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string34 = /.{0,1000}bb141fb92bcd492552d5d6c09fbf39f7f674eb49.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string35 = /.{0,1000}bd976ca9268513e6cc4a58b85574f62b8a76cc92.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string36 = /.{0,1000}cc9f09bbdb9277265fd71b7575b1fdda3bc2f946.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string37 = /.{0,1000}d162d2e96da627fac5a93d5e6faf379aff092bbd.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string38 = /.{0,1000}d67c342b9ffebd2350cb81d6dbbb35071246fb19.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string39 = /.{0,1000}d9fd35586f323c9990b3da5c7c1f07c05ff88bc7.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string40 = /.{0,1000}e4f33ee9ba4d86685f8df4a89e192a354139edcf.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string41 = /.{0,1000}f27479a8728d9126cc055daeb5cddd01cabfa37d.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string42 = /.{0,1000}f59e403b62053c785de7df979c5cb7b0f426cbeb.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string43 = /.{0,1000}godoh\s\-.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string44 = /.{0,1000}godoh\sagent.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string45 = /.{0,1000}godoh\sc2.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string46 = /.{0,1000}godoh\s\-\-domain.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string47 = /.{0,1000}godoh\shelp.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string48 = /.{0,1000}godoh\sreceive.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string49 = /.{0,1000}godoh\ssend.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string50 = /.{0,1000}godoh\stest\s\-\-.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string51 = /.{0,1000}godoh\stest.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string52 = /.{0,1000}godoh.{0,1000}\s\-\-agent\-name\s.{0,1000}\-\-poll\-time.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string53 = /.{0,1000}godoh.{0,1000}\s\-\-domain\s.{0,1000}\sc2.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string54 = /.{0,1000}godoh.{0,1000}\s\-\-domain\s.{0,1000}\sreceive.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string55 = /.{0,1000}godoh.{0,1000}\s\-\-domain\s.{0,1000}send\s\-\-file\s.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string56 = /.{0,1000}godoh\-darwin64.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string57 = /.{0,1000}godoh\-darwin64.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string58 = /.{0,1000}godoh\-linux64.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string59 = /.{0,1000}godoh\-linux64.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string60 = /.{0,1000}godoh\-windows32\..{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string61 = /.{0,1000}godoh\-windows32\.exe.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string62 = /.{0,1000}godoh\-windows64\..{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string63 = /.{0,1000}godoh\-windows64\.exe.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string64 = /.{0,1000}https:\/\/dns\.blokada\.org\/dns\-query.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string65 = /.{0,1000}https:\/\/dns10\.quad9\.net:5053\/dns\-query.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string66 = /.{0,1000}https:\/\/github\.com\/curl\/curl\/wiki\/DNS\-over\-HTTPS.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string67 = /.{0,1000}Receive\sa\sfile\svia\sDoH.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string68 = /.{0,1000}Send\sa\sfile\svia\sDoH\..{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string69 = /.{0,1000}sensepost\/goDoH.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string70 = /.{0,1000}sensepost\/godoh.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string71 = /.{0,1000}Starts\sthe\sgodoh\sC2\sserver.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string72 = /.{0,1000}Starts\sthe\sgodoh\sC2\sserver.{0,1000}/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string73 = /.{0,1000}Tests\scommunications\sto\sall\sof\sthe\sknown\sDNS\-over\-HTTPS\scommunications\sproviders.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
