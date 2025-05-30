rule traitor
{
    meta:
        description = "Detection patterns for the tool 'traitor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "traitor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string1 = /\/gtfobins\.go/
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string2 = /\/tmp\/traitor\.so/
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string3 = "/traitor/pkg/backdoor"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string4 = "/traitor/releases/download/"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string5 = "/traitor-386"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string6 = "/traitor-amd64"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string7 = "/traitor-arm64"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string8 = /\|base64\s\-d\s\>\s\/tmp\/traitor/
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string9 = "01cf2c956d813b4dddcde5f3349ada814764aa45d9579e8dde063c891f62d1d4"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string10 = "03fdcd35cfb237327c0813ce931a62ffcf837302f8e0285ff1c8085ee30f2828"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string11 = "05c10f59c21e200d25112a44581eab14d4793bfdc4f4cad8a9e6b0d231f4f1aa"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string12 = "0d8cac6cbe2019d99a5260f4c934d9a4c9c7022d141006cfc0f87fdc3f8ae4ab"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string13 = "1189360f7da03490a9f0f3ce283d487335a4db24232d6fabfd17bc7ec4e53392"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string14 = "1312202e1f36db3f8bb319c6a886ba558373b83dd9d8bd54a8fc42ae156d81cb"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string15 = "17914e2d97784ef7aaf52f9f8b04db77cad036308c6b3584fa0fa172ad1da077"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string16 = "20b948d35e9e730e5aaa00f8de01107af773b93313fed752ae63afcd45353073"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string17 = "348980f606af2f76e3fb4ac9e1e66f3eb42da0091e72695942a3e97ff7977c0b"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string18 = "3cb401fdba1a0e74389ac9998005805f1d3e8ed70018d282f5885410d48725e1"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string19 = "48a7984aefe898990b83d8d8ed16f8e8116288fd7531affa4726b262ba3e682c"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string20 = "49a2c7f9b752b7592cb1726d5427c81cb54e4055ef8350226dbb46a32d8fd560"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string21 = "4b9e2f5e4582b162aee0241e31482b2a50eb34712b13d2911726b3b988ccdfeb"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string22 = "4e1531d35b504cd39a927b3f3dab61a7d8642b405e5f999ff52fa47381e0caa6"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string23 = "4e1531d35b504cd39a927b3f3dab61a7d8642b405e5f999ff52fa47381e0caa6"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string24 = "53b439d28020a437a1d940fb4c9525283c8093326c1c187da245282e840ba0a4"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string25 = "53ef079f580e806d9fae5fd698616574623fd44467c446540ba1194c20c6c388"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string26 = "57681a07f437b52ecf05f2b1a6f268c5d3596c9627280d3ddc2750a20b7d5dcf"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string27 = "57eda2366c187ce90c39a4710ff1fe62a7d667d25bf9ba63dbe34bf44b0ff684"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string28 = "614998828e6d1205980fde58932c9485346edf8e3565669b9a30977d4b952b08"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string29 = "68538ddd64073d5e6b9edf092c7a364c0380734826a00bc10e12a7cdc370410a"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string30 = "6e08212071f8b95216a56d0a5edef8fbf23cd33f212762a236060c486f9319d0"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string31 = "73e0810037eaca1b0a643396b61a0b6462582d89d952c0c20f96f800dbf5e2e5"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string32 = "774f93b89388143ef4f6a9752b171f3a337bf7523b236e6719703a239d56cab2"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string33 = "8093f462616ec9e222eb6dac9abcff21a6dca3075283e7daca3d209e81cb85f6"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string34 = "8093f462616ec9e222eb6dac9abcff21a6dca3075283e7daca3d209e81cb85f6"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string35 = "8ace2f6b59f88eea47c07022c330c7fc91811d1a9f39148a3212f844a2dcd9a4"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string36 = "8c038621b5807a443d8bf7344f1df9defe0e8193a55efdda8b0e08d0923c3c9e"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string37 = "8e0accdd48e1d04e3693326de2750b1e68f75fde6e012dc195cb876088704bdb"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string38 = "92d8a70870f02f8bb284a317c9801cc774dfabc2660efea327049289f5137376"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string39 = "93cbbd682b981bee01388710acf813b64db918b54b61039d3fe1e019dad077df"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string40 = "94f93f559533afd33b026849ee730d3c360faa4e9dcf7241d3d3132802736ee0"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string41 = "a12141ccddd231b9596e3ded58b95835338ff5f5fbc0b9470788e51fe9b4e651"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string42 = "a46d2986f634a23bf7156290284914da2c25c35b9484c11e119cb2c2f5bd5c08"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string43 = "a58a13faa35a214b12f57674937f8ebf27eb62e29e26b7a00a624cc127197b50"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string44 = "abdfd724cc84b4f7c2fdd641acfc2427baad0e6eb6c031a53e0c25b17ebb550b"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string45 = "b3a161043abbacb0b787da084f3222a1d3432aaff6f9fd16a244a42747ab6d8f"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string46 = "b3da8fb4ec21437e3a9b7118e9eb2da1a3b83fa202e546c64533d40e719263d7"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string47 = "b5072f210606f0fcf08e88c188e92ed4df8a35b1811008262401b664268f1f6f"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string48 = "b88377088eef28045877c620f1a713356ce155885a61b073d3f4569675bda0e7"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string49 = /backdoor\/traitor\.go/
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string50 = "bc99c9d2b150645abdb37d35c032dab28f5995d505294b0bd2c633525c91c4b0"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string51 = "c56e66d683919054d0ae34f15f5d08624ad6a8c211ba8768fb52d09190b0a74d"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string52 = "c702fa1d6618739e09cfb8e8cb79d563b1da757539bbee812748a79a0624e271"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string53 = "c87966a280098a45c90dac27666f3f01f6b6999e7b08719a8035f1355d696ad4"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string54 = "d0c376cd617a39f0aae2ad7dd76c689025f894e3682c6e192ed6ff984ae81fd7"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string55 = "d2cb266890e46c37292349b26bff380e5a1b2ab09ec20b04a530bbfb0252fdc8"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string56 = "d42f35102915099261b206a59fd3e7262af7a6d7f749f2236ba8b6d2349eec92"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string57 = "d4e5da3ad9dcf854a1d6d71805fcaf8d418cbb3c7916d85ae641d88a745c23e8"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string58 = "d639357536f4da8d953172982a82a87c028a8fb3e4e89307ebff92f5d6c99287"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string59 = "d7dc358e43314be5c096f1f011947f422a12a261db64528bb531418eab164638"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string60 = "d8309dbfb648a5f80ac88634ffaa3a9d613cd31a785b9902a687edbc2d71d73b"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string61 = "dc2dd05cc2f6dea85f0bfc16b0e1008687a32fd92f49f0043ca60a061fd59c66"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string62 = "e74bb25e61d959049d06ff838d2147b291dcffe3e96ad0af68077cd9f50d2e82"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string63 = "e842c810b6ecb9c7634f1cfbf81b6245094528ac5584179eb8e6932eaa34f421"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string64 = "e9a83a9f298baefdcb73e870ad9ec7253247bfa3b7450113c2b5a63e26a8b4ee"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string65 = "eaf50935fba5aec83bbdf8fdc1ee57284098b88503c25fab1581d4c2b5ddb41e"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string66 = "f04a52623464ec2eb52b22e7348993bf5b7456714505f87342781b8d21c7233c"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string67 = "f1452a47c21f37e9d581f706dce8862a1d4d045033470c4080809fb4a205e42c"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string68 = "f666dbab003b377019955f3f304ac68c9af5defd5e05a39e916e7af8ad9076c1"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string69 = "f833fdd261a1135db87bf4e5cac17447a2d837f6b43513bffae389cc8a8ae00e"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string70 = "f91025122cd3b0f537db1eac70c44250530f34ea7521750bb4af7ff1c7af3b8c"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string71 = "fcf965a77c9f97dcd7304a7abbe6af09c3e41855c888db2acebfc995365d1a28"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string72 = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string73 = "fe44d88aa5c763905fc4a7b600ac6545f9d169eca637796e28a08a432969f5bc"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string74 = /go\sget\s\-u\s.{0,1000}traitor\/cmd\/traitor/
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string75 = "liamg/traitor"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string76 = "traitor -a "
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string77 = "traitor --any "
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string78 = "traitor -e "
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string79 = "traitor -e polkit"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string80 = "traitor --exploit"
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string81 = "traitor -p "
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string82 = "traitor-amd64 upload"

    condition:
        any of them
}
