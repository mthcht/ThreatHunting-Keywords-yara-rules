rule Amass
{
    meta:
        description = "Detection patterns for the tool 'Amass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Amass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: In-depth subdomain enumeration tool that performs scraping. recursive brute forcing06/01/2021 crawling of web archives06/01/2021 name altering and reverse DNS sweeping
        // Reference: https://github.com/OWASP/Amass
        $string1 = " install amass"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string2 = /\/amass\.log/
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string3 = /\/amass\.sqlite/
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string4 = "/amass/releases/download/"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string5 = /\/amass_results_owasp\.txt/
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string6 = /\/deepmagic\.com_top500prefixes\.txt/
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string7 = /\/deepmagic\.com_top50kprefixes\.txt/
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string8 = /\/subdomains\-top1mil\-110000\.txt/
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string9 = /\/subdomains\-top1mil\-5000\.txt/
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string10 = "009f7df0ef3989ea2100166e4e56ec4182d3819f3027eadff3b53a50f20bc0c5"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string11 = "02761d4f88230378f0abb1b33c505e497d07c4c160e46a0a7d487870869154f2"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string12 = "03395acb8e89d081c82626cd1a91aa654c0a3b05c237632d546aa594fc207fff"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string13 = "0a660e5933bd61f6a564cc86bc9ac4a573e104de8de35575a4a09d61357958b0"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string14 = "0bde1c200a95461bc8ae1bab8713ec0adb7c4c01616f37d7cfa395bfc94a0dd2"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string15 = "0c5259c25ef3911a8936b0216cf77edb932743a82992d6f77e8e420795697fdd"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string16 = "0e2c629c26b6fc61459dc59764df329ad9d2bc80a9beee2063cdd1b5d30b2245"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string17 = "0ef24b00e5bfbb3cbfbc6880f5ff42bbbdcc57c288c2e610d82a697da29cd074"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string18 = "1006275da2fa2271887b43047f3c81b8525866abe2e2f239e9f2cbde41de484e"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string19 = "102083f916b833362439518408fa1e5f98a21ed600ed51ec19219d6f3fc92f21"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string20 = "104e9d143fbe807efa94f576f0c400b222fbc6a76f64bc4764fb64abf154e7ff"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string21 = "11f87919942c811549a9c15b8647d26639becdc0feb75c43c87aa542d64e0552"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string22 = "1377aa737a1f18c35e3165b43f3c814a8bda8fe5facb019bbeffc2146dfd42a5"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string23 = "146371bea2dc7c088fd3e7b14e3156b838db646cd818ee5b95d7d792d31834eb"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string24 = "16ee86e4a45505a595d74043dabe9e22f0c8860f593c215ccf1c3eedf973e9dc"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string25 = "17bfe2c77e35c8496b0bbde81bc8d3f5831f0b7f9a4be342a499342a6030fd3e"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string26 = "18c5b272fb057271e5017d232deb701e195e05f7a7c0a98b176325dfc2774a30"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string27 = "18f07ed52889ed4acd8967813d25ff8c5494b1fdfd1c0727eb7cad73d5fd7a2f"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string28 = "1b87e3a566e015aa71409428ad95cc231860e85bb64396197bb3b511021a7c45"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string29 = "1cbc16fda9baa7412d012fb0de8958299e885fdb47bddae7d5c05431f2efcc32"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string30 = "1cdd9db6aa54fd65d12bfaa84e98f8297a2780dadf42c42d6f275ec1ff43d36f"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string31 = "1e2a2f0524221d5e07dd7a11d64cd1c1af7137d3cc022ef550a9aff5bcfec0cb"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string32 = "1eee1c70a5c3d9b5110eecc51ca38009bc720c5380444bd7e022f593d2f981c9"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string33 = "1f0ff9ff279c93bf55a124a2ac36a4b7e97b77cfd7cdd221375b1449b7c286b1"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string34 = "1ff88fe10eddeecf2f6d8c4e3fabf55a30f6572fc8b4df4b8117ff89b774a234"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string35 = "205cbd1e78fffb666439a6bffd05c0486adcd36e0f237e80619edf8eaed9bf22"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string36 = "25472451c57629aa2b0134cb123861d3b115a60fc0a7fbe320d9aa175afa887d"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string37 = "268a67a9e978f95dc4ac09e9e0197ec58db072fd4a798c7c08faae35cfdcf4a6"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string38 = "26a7ddb93dd3f6a9b53d864af66267cc0b675be9092863edfa43810eb2363ade"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string39 = "285e1d699b5c623b0df102e330ed97e7fa64e13dfe9b2c789a0a7dc2544e44db"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string40 = "299a1d70cfed99dc99e32c2b930207c539886f8277794f7b25edbc8ecba0930e"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string41 = "299c708dd83186dda79639794e8ca637fe729b2bd2f6c5353bc5c52f64c7e29c"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string42 = "29ab009420cb687d2c1ec6e7aa68faad1a62215b7a92e70aa3731639d5ca1a69"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string43 = "2b5afb8a567d9703dfb416099fb0452e2b4b4da5170f0b23cd3b812df2e9319c"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string44 = "2c48923740a4fa2979907d801e7552ed940f19dca8e914898ca48b46b1f2330d"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string45 = "2c9c88011cd2b1c1af8c1a3dc31036ac22730723c50912e0f5c832f2a40b8b96"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string46 = "3063cb48a6a184bcc77efdf9c5753b7ffc1c4e5a4f5d10619b7741d1d1789a40"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string47 = "30995a0eee6dda0cef60b94e666eae8ba42efd818217e7fcf798e8bc8d1e1e17"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string48 = "31ad473e63f8dab709b9b7a772cbd9a33e66d7f3510aa6fc261003e17040ed1f"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string49 = "33b38994e71d9317e92ce4c8062e8005e15751432f88b35e8536e851425d5adb"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string50 = "346f046d9956ddb6746649bd1f69d04f7df776532b191cc4bcb8f80792624f15"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string51 = "35a1cbb81eb45e28f4e9cbecf0cc3d9d4bf1fe27413ae605bf6df9c226348768"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string52 = "36afa4616649f78e31cf7b67a66fddd9e9d6c532a791aa37c8b64ab6819a2c1f"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string53 = "36f3846afda7e148c57f944720df6f3de2085d7c49f9a207e1e8bdcda8bd82a4"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string54 = "36f41c33dbc19f8de5e440a192fcc41528838a5840bb21ccdbc390e28086c7cc"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string55 = "37eda44266178cf5b5b932e2dd45c12d65d1379221ed6f77a174d517e3787ba0"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string56 = "3e3b1b12a07d9b39b6c361763d64a882b91d8f73f207b061b8e2498ecfc9c982"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string57 = "3ecff7d62c79b34f0c8bb105a9c624f3148aa59c81ab38d75bc110578bf66ecb"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string58 = "3f48b595aeca862631b678662a78fe1951a607a10f0a6593a2cc86c7acb4929c"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string59 = "3fbde1d2887f69fa6f96aef04c2c7924e1a439cfadf44990620d0a2fb4a4db84"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string60 = "42b0df4d8c38bc8123175b5ef8c2157bee1bb1b714ea4514bf7e6e59d27679f7"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string61 = "42bcc191d46a5c1e8fe0f153a2d5954e4c6ef26b5b07d8c132ddbf1e9671c2cc"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string62 = "4486f1bdaf83de269c93c88c139550a8c089eb82b66664ea4857ae00a5493253"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string63 = "4658ae8a4a3005961327d9b009027b5fdb9e847dc055e4f303ea977639662ca7"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string64 = "4755e1f4336849953c87bbc5f4d63698eb44d6a3b2533e591ee7cd07a16a9937"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string65 = "47747e172be46f80fb7817cb3f0069f5354883d733f98f63ba3dc1849d1c69a2"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string66 = "48cc9ab2452b8bb8a9230f2a70a9b9e74a9307f9a0792cadb76c042f8b93e1bc"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string67 = "48f3f5cf9a7cfae9b9a5efc36f0af92513bef873e49afcb0bf234d97bad7b951"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string68 = "499aded3a5f4ad62112d592128c245a7f38d841475428df10b9dded5291fc926"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string69 = "4a190816cd6f296571f8f457a82b950e510473884e1ebf0de0fa51ac6d8ba250"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string70 = "4b1f30bb50fd9df218259854bfd47b7b2b9e818bdb64909e0105f120a2ca0014"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string71 = "4c244a97bd354cbbefe7cfac027dfdd157b921ee5f9b66f7dce785136e657cfd"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string72 = "4f1ffecb374f22e4e622bc96869d412bc9e61c8fb14688336e65585fe392b20e"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string73 = "4f7931570b3ec42b04ef2607e39aec95ad4c863039417eff45978f58bec99c95"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string74 = "509e9cb4861e4e01742bd96d7a380c47dd4dae47a7a6b18cd474763041c010b1"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string75 = "50d8184f7bfb2ed1c762bd9d66fe437861bb3def73ad14bc9baf61f19d1fa9fd"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string76 = "51033040fbc818f2b5fccb826fbd87b7c57f9599c6b8e48aa0f4bd1a397a09bb"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string77 = "5584e3e3bbef3abc02ab49d0d5d06f6cb021becd41da4600dce3096830ce39c5"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string78 = "571ccefde4608492c83836e28b50ebbf92d740d99de43ea35df85f2cf32d9b77"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string79 = "57269059f0f5e8e510d304e8368975291e4b583c4d5388375ea122e46b8ff357"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string80 = "574584f229e8812dd5a924880611e84120da7589b86a3417fecce77687720ebb"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string81 = "579a0817c99aa25f8bce0b453da2bb65c622a51c2d702512899a244d675f3305"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string82 = "5b08506beace8cb3c07dbab702e9d487eda75084fd80bc6054445adc4bffbb15"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string83 = "5b46bed3c8b76ee3d3b76dbd1dd5c45d79a6a623889aca85917c8777b12cdc86"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string84 = "5be7ac60cb04f99ae1e563f21289ae608b3dfdd2e79becbeef1a611e9a7bf186"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string85 = "5c575e2b8caaac3ca42bbe9f7332d822d972ff09afb6afdea8561e929c35d922"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string86 = "5ce161bd3a1804cb6265d0d79615bcf9dc3b115ffe85011638de46e4b16c68dc"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string87 = "5d7d828bad9b38218b3eee49222c7759318cf7156d8a90aa94022468897b14e8"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string88 = "5e2406b0687127f8980b1d73f475edb5410d6337cdf022a3d8b354c88c64c30b"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string89 = "5ffd03dd56f6f41ea426cca9bec8df3eee40a670204aca73a1d8a6dc076a3011"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string90 = "6461a823b6693d08cf0fe8be939138b7cf2ee31cba7f162e1f2f7b62d7446a7e"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string91 = "651834f5cb6e7559c8be9de345396ad4c034d08fa92169f374404989a0590c5f"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string92 = "6698d5497a277c219184b29528e85650b887b7222c36b55ed1d2cf8bda0f57c8"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string93 = "67086ee2d7fc1c67e2aa1f341b6c692b711fe890c419b9e3b7a80c727163db64"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string94 = "686c2fd56c44f2621950ffcebad071e91db115a57f2a4a72e27dcf65c94190ed"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string95 = "6ae1f12ee3a93a2eb5375d65509afd69c5b34bda454d44c585793f112714d4e1"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string96 = "6c40e6c2415953b0716a499a3b8b5e5541a5c4a523971ff7c3076d892a3a25d3"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string97 = "6f71c0c87c5593fe851b54e638e9c242e429018eee80fce80a1fd2793227bcb8"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string98 = "7025b5a567c2599dc85b9dc1ad4f5591d46a186f8fca1a8773a6452e238eba03"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string99 = "7405ebb59402ba05f601ba5533c31149d406a16e9b0159b7ab347f16c0400ff9"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string100 = "757d4c9ab64fbb35ad9fd0840e1f92b15b8f27047c700ab0a4329320203115fc"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string101 = "77d6df99bd2b655d9f00ac88e6a908a7e3ba23a4f7b181942b9ca3063d7d80ce"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string102 = "79a0b0ac70e2c7315bd2a6e100737159b71da490aad293d6583e995a6a7244aa"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string103 = "79d297c97d9217e752410cfcc43ca6eb8b67755bc396d37ae4fe7c2348413bba"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string104 = "7a8950ee0a99e8abc75e9b6dcf938acba9864b827b689a7617b584d24af90627"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string105 = "7aa3fb1f8adf702283d9de96a76ec3be0f4e6e1f0eb802f003a73f30f367122f"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string106 = "7aee9dfce2969dec078595083f096c526ad4336795da50b5a0bc6e5741a1215e"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string107 = "7b399e28444f5bab4eb28f6c887e2eb0e5cef1e2b4c2ea8d51cae9ca5899deb1"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string108 = "7bd2ca96a2c189f15784e3a8294218b5760fb56e32e7fc5d29fbca0453a9185c"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string109 = "7e1631ef7fe36cd300de646c9a3f6d55d162b28f8909adda2a9ca7443d11257b"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string110 = "7e3584959c0b499046b43d241e6199b64878655ba0c56319590ecb75eb14acd9"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string111 = "7f18b60690bd7e02064e1e8f6bec4496c77f6b33d2efcac94b16314919d0e2dc"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string112 = "803fb03b9ae22f31ebb1db44628636c063311b3fab30626f9224dd954b7028a9"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string113 = "81a2d83a2d25f5ff053db7c730e776a0be57bc383cb3754f491a9101ec5888d2"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string114 = "86dce81496e79c16628d56c2a4b9c0ef2d22a5de0b3f84394b306f2705a18829"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string115 = "875a8faa095079fb31413ed16454c8d9ef0a23199984ac734e882c99914975ea"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string116 = "8f71ce37ef8df7223f14a8c3021b94b2b7d3bcd23b813df32497826887e0b14a"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string117 = "94dd1b6c6dc713a934516955f05b43b6a7c82b008788312e6f2fe56ed12c9094"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string118 = "95ce7bcdf3de537ac2cd09e33663d522dd5156f49a565ff54007d9f70345a1b9"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string119 = "960d0b51aa95a71cb471e9d217686bf7ac9b548613977d521bd477caa7a5cbf4"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string120 = "9708b182a7e712892b7750c50a36ffadd3983e2874269740c05650f979ede361"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string121 = "9be91dca307ee31fb990f6697984a4a84a486a594f5937c3420a9cb765f63ddf"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string122 = "9c1c5960a8a85b20b9ad5bd47d43f5b32ac403350bef95242ad4c8cc9dbe6556"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string123 = "9cb8225eb4a16ee8537cf0f46ca3cf1c750db6b92deaf4c7d8029cce95b2dd3c"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string124 = "9cd7158c53df4734b75aa23abce157d261f37eef1432b741078737cab19fa65c"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string125 = "9ef4e3284e5ffe762b6e18d341a1a9e3400e5cd76241d6ef0af77103119c3515"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string126 = "9fa9202c24ff2eb3dd3dae886831de5799319e7f99ebc1f4a779832539b34560"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string127 = "a0080e0a7da7636d28e71a955f9cfded032fd4311239c2cd35fe78caa8f59abf"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string128 = "a03aaf164bf92c0d354c6fb6d6b6819a1a87bf465c803de6a0bc47261d3dfb4b"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string129 = "a085122b8ad43a0b5ab96a6e4f96563a6bd844b45c00b9ff7b16c20c31f83e0e"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string130 = "a0e6607e98251fd8dc2d2129d45c473611b9980ffdbff5738ebfb18c440a69fb"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string131 = "a0fd47aca72b23be5ed3afcf1240130f12a8e8981ea7674ff1ee6e7d34935b3d"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string132 = "a1666ab37da97129746e6efae58c29e4796ad1427d41326061f80f9706ec3083"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string133 = "a260d61fe0bc252fa2f2ea9abba5db96cf21bb8d786fcaf973c5e9cdf9af63c8"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string134 = "a3bf89c831592b1dd3a093f68a4d4bbc2fa6c4ebb6f2128808d4aa67f81b9269"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string135 = "a421db8d72e7cc2e9d64891c05a49d6a60aed15dc4650f26155aa560f93ecc80"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string136 = "a53c9d30294edfc74b34a79352c05882e23ddd37678ae419c083345bec6b4880"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string137 = "a5cbbccf1b4a7493f36eb7b51beb19c77a8ac044a4edfb2a5f13d6a00601eb29"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string138 = "a7e469379e562140126522b28d4c00c3ad88fb323ec6d58f3794a76b65e81c67"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string139 = "a870ee7018be0e35ed196a844c194b0c69ade3ec46b8f7895f6e002a73c114d5"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string140 = "abc6b4e0f41a55ce44e359e7be8a5b4ee0e0174a8a4ecef0782081f7b2cee773"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string141 = "abef624f84b21fb45d4b9d39693863c6bf4e9ddb94830f797c129d03937a7f03"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string142 = "ac518d48ff20843cd624d2e530d6a507d412ef7749421bf39cd7f23eb817f11c"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string143 = "ace6030f3a6859f95a7c0ce956035e71a105e4daade9631c324e7e548aef77cb"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string144 = "af47f458fabf670417c688d3b25cdbd4ff7a4f34530b2af273a578e2a95ae697"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string145 = "b0cef23396325be6652587249d65dbcd53571dc6928350ea297f99ef1b58f920"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string146 = "b256ce69db7a774dc39ccef3b0281135b3fc57b7c7826322ed6736ec5259839a"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string147 = "b3d052b346f0dce5b8bb7801ebe26fee1bbf156a0072eaeff0bc29ce3a837b9b"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string148 = "b67dfdf5659268bb48626ef39bf9c2c74c0b5d34d21c232a17e07ba200be11b5"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string149 = "b923736184bba7b4588e1d53759912b2c89293387a1d9df7938626d475fb9c6b"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string150 = "b94e6e9fe00aa1789f2b29bada37cd9fbf2dffe29cab668b1500621830dd1040"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string151 = "bae4458b1ee612926f85169e02a903fb9b22d5a42f746ec210bdd02d15f7af6f"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string152 = "bc0ede720752c8c47e5ae348c16efd9c52668f6267f1118e3f5af0ee22741beb"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string153 = "bc2502f347b077bc5d332192e25a696c072314503ad10b6573c483fd61f9d4cb"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string154 = "bcb11a82c2649c468c4b130cb209a42d63d34909373e7e34a4fd80bcfbe19222"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string155 = "bd4913ef724705e97369862944b14594b3e092caceb0f92c283964ec00cd08d0"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string156 = "bfd8c2639bfe925869dbd7c0ee8ca9901e6939ea07fe52a2c469b1bf12c002a3"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string157 = "c1e4c31f5944d6f9b5d8e08f09733807360052c69df4c34bf09f31e960f02b04"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string158 = "c27a1a9ed68825e382cdd8db8da2c5139a431d36c300f95bf8e0e7a04af88b2d"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string159 = "c330560d4cd9bf1a60b1d6d23d4f7b584f668965926f45fef8db96256fa66b39"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string160 = "c3d0bfe503699cc1ed0452f3775e008b4e3983e21a2df33a8b47fe21555a4833"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string161 = "c3e7919dd51fbeb12a7d6d4038a144cf4ae9c13793bdf137efb034dda6ed515b"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string162 = "c5322b9356674659db7025d0571de7020532e4ddc25ecfe69a7fddae00e95476"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string163 = "c545fe6ed777aebd67e71c4f31eeaf05ca2a384d9837d752f238b484fd4514a9"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string164 = "c69b56a061711d9f4b9657ec0ba7aa0ce715185b025cc4c123de462743cde4f8"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string165 = "c77c84a7ec144daa151410334db7f90855c8406c5d205d9c68082902018ac2cd"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string166 = "c8dcd4f55989ca974ccbf330b883606943b4cddd96049618d4f9b52bd84a444b"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string167 = "ca5ba9e7a694713dc8d1edc1be2dc4cef3b390566cb4b22088a85817d1b3eeda"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string168 = "ca72920176afc726b5966675af9b6f025d4a3418235c3864f7df2a5c0010a5ee"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string169 = "cabe4a6eb9bea5241230a45710a5df1ecf984be0cdf3e3e5fd9d130daf05864f"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/OWASP/Amass
        $string170 = /caffix.{0,1000}amass/
        // Description: In-depth subdomain enumeration tool that performs scraping. recursive brute forcing06/01/2021 crawling of web archives06/01/2021 name altering and reverse DNS sweeping
        // Reference: https://github.com/OWASP/Amass
        $string171 = "caffix/amass"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string172 = "ccd7652de457311135874574da9dc2cfdbb5cfc121c0ae158e85b78c311dd506"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string173 = "cd9c7992a24b65ca21c6f89bf538d396ce057caeffa46f869f0c860d067743c5"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string174 = "cd9cc854525e7c75ff146697f8856ead7e1a9a739ab3575cc598eccca1aec680"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string175 = "d00c00f1992a98fd03f1d19ec888e3931202b970fda01d59914275235cb0e4f5"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string176 = "d06bb0bbcc2307ccd8c36299b624fa84849fb3b525ec2321be8a1ed0ca88fe3e"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string177 = "d0979cde89fa887b2d61b7d225f433e96106d4735cb92069c84ccf69405aa74a"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string178 = "d0ec66b90af2a1a10aacf8c8130d88cc0886235d5e74df5f504d01f9e4173a93"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string179 = "d22b0e65e8b92c408276652f2b344073684a77b5ce7bc21fda8a8b03f1f76495"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string180 = "d3c3d97fdf1783eb56340521d315a0071b1f700ab3cec537723b866e3f56ebc3"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string181 = "d54c329f98f7efcd433ab2813d2be5a6b1454dc7faaa006c239551f08cf2527c"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string182 = "d556dc4b57faf4f138956434499e48b52cc97aa6921dcec3d84d04c0e0601d38"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string183 = "d57fb832ba62ad32cefe4f98fe504d503d85b429306780c63ac8a6ffc7af6cb6"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string184 = "d6255ae708bec781472a76a4cf10d9a53943a05ceeddc0737384cffe3eb38e29"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string185 = "d79b1291fc162909146710ab8ed6eb9af77c018bf5991e670e5d7b25f3feb095"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string186 = "d7c079211118ebcf3827008bcb577d08967faeb1786506057e8e4fd730cb6420"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string187 = "dc48cbd7466cffbd9ec80dd26109b9e633b9bb02e73d8db992e2e5c83ff81bdb"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string188 = "dca882cdfe33d94f69bd196da5ee79f6120ac057e366cadada88ec42e8f1ce06"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string189 = "dcf25634e64e3b63715dd4fb669648a819e99b860697aec8fc5da5f5565bad91"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string190 = "dfa3434845774ae53b7a2b3396c31a7478f7fa8b1601b8b9f8600a647f7b492d"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string191 = "e127778b3688b8d058d5043af5c65d12fc280c37f303db140a6535974d1ae554"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string192 = "e1cf6f45fb64f8e043740015fc1c48d68f8a062be61bc320dbf54fb25ee87fbf"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string193 = "e30a09e1311d6fdcef61667429210285a5b84b84b9bf9d6aab7d35e5715e5df9"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string194 = "e50686bb739ce69050f960b06ec6dcdbd4a7bfe8c0a08abbe9b9cac45f04d787"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string195 = "e5a9c124911cf7d0f0f2f202a067744df6ecb534b93072def963b5eb449b2b3a"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string196 = "e5e994caa93a88d8a0dea6d4267336d13e00d5963cfa5d9ad33235f072d5eec2"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string197 = "e6feac10da1244ba8ab1bfaf6eb2a60ba4d4f016dc1fad06df3e19d1ce318c7a"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string198 = "e79c6e7acdccaefe648166249c67a7c53a9783940f51ea7d4bb2817d684cf12a"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string199 = "ea2eacb07d4b1fbe1d8db075a3c497746b8268894797b573c86451b5628f8f5c"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string200 = "ebac84e6e59f9bb6093f2aabef5c9568c27ab1f922d3124c9e8f9675de150059"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string201 = "ec945b53d3005194ef0710397f7179e57f7249012ce85ab47ee6b1519bc48d31"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string202 = "ee0349d1878fb3eac38c76f8d1b2fadc5c20cf08b7d0ab5a528e8a30e9a3a8e9"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string203 = "ef06984084cb323bc4a055076b4817a9f69d4914707030daa0374a059e4ffe37"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string204 = "ef0a2554636103e9c7ff1590aebf1eaa2c41265092f20598e67c8ef0dd168379"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string205 = "f01d1e178abb9200266fd816ec512b33f5f1b76f8d5d3953678c42003e526692"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string206 = "f520a23b9c1baf7a7a8ccf6f71e082f337a42e07d5437356d98bcb0eceec30af"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string207 = "f53fce2c36ff530c68c813d8444a43f3167d32673727c447bd551ebebd9a5d80"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string208 = "f7306e6b984b5e7316ef8adab27eacd18bb6edfb249d704c26abf085ded69bd4"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string209 = "f8226a0991ddf508b895d10a3fc5e6bc66ba20bb77f549140f7ac5e95c73817d"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string210 = "f8af79bacf239d71ec2fab98d0ac0a9fc908b362b7228a0db33269700640e8ae"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string211 = "f9677acd8599417cccac1cf15e623e68f2610f8425eaff77bf7a4364f1a1f0d3"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string212 = "f9b44f6ba01b4841f672277a3459c5e2fb6325c1c7e2051ec41ef5a85574b66a"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string213 = "fa7c589beeed7dfb870fb784b265063facd3b007c454256107e76bdc5991f422"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string214 = "fa9f88fe906846df3284e667263453cd96464c12d7f152ba27b2a5669a148c73"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string215 = "ff880fa3ebb735862d21c84365bbfefcb7fa2caedf42d51f61f6fc5d6944706e"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string216 = "OWASP/Amass"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string217 = "Ports can only be scanned in the active mode"
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string218 = /useragent.{0,1000}OWASP\sAmass/
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string219 = /user\-agent.{0,1000}OWASP\sAmass/

    condition:
        any of them
}
