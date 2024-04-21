rule brutespray
{
    meta:
        description = "Detection patterns for the tool 'brutespray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "brutespray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string1 = /\s\-f\snessus\.nessus\s/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string2 = /\/brutespray\.git/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string3 = /\/brutespray\// nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string4 = /\/brutespray_/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string5 = /\/usr\/share\/brutespray/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string6 = /0e2e76930ff8d2bea66b82db863243f3895d39e761893eb6de025325747774b6/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string7 = /15079a1ec5eff9da11edafb3c59984d2ab9ce7b02fabfd07cc398ee31e7e1dc8/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string8 = /17d97bd15502bc16353e7e06822578069c1e653b031fb4ac982d8cea9d31026f/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string9 = /1ba38ae7e6c55fd66b21d40178341d18c195991c23044e030c3096746a2e1266/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string10 = /26f5c3b1de7bc524883c2f5620ac07e5bed58bc8149a9d1ecafa47d586a5693a/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string11 = /2a9cd5021cf8f43304a9ecc91759b534aad0efff59d9da57ca666c8b5f8ce819/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string12 = /2b6e6ca400190f98d1bf00cc5d50c728364c75db258043fe26b5f014c19c7188/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string13 = /3db93e0b8f7b39335bfa3f1712a38b8f0e21210772eec85524941e420e9e58ff/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string14 = /44fad118e1e7776c04d4a8fa8174ff5316ab5fa23b0e58e5c8a15c50f04ed365/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string15 = /46f31a5656b5592c4b37514bf7726bb1d51140b7eab918643a931cd269289b19/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string16 = /4f28ea38405ad0908c509ed774da63b57606fc2257e76d613e6968ff390867a9/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string17 = /57d785125cf62ffdb727ac7f56110dc0ab0403f033caf958b717fc93f963f097/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string18 = /5d16081315e1588a26019bb5195f2f72f278a3c86acf8cc1c072b791960beabf/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string19 = /61d81c3ef4a77bd815d196b650e773ed31a507320c43c52bb9f6798eff4d3413/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string20 = /6788355188c40674e65fd8d2bd610ec4be42d1a5d78116990c0d109863c39a3e/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string21 = /6c44d6bfc218285f9f359e67c18bb652b16602dbcd524128a2a8996823a683ee/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string22 = /75007cb1974bca92234e5e178b17a429922c54676bc446d032464e358d26510a/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string23 = /7b2ce8fed0da2a756ac78ee68f0885399ee5fa57e6a182e3b8fbffc1c523710d/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string24 = /85ef86a80dfd91208cf5eaaafd220a584c591ed83c22ee039b31b9849d7428d0/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string25 = /863e5c3db9d52c8af4ad2976dbfe510a8eaaec2affba50a5abd916e440e18804/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string26 = /8ac384fed6ad25cb08874eb3dc9b45c80084fa5518ec5a7fa79e3f5d5e40b66e/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string27 = /8b53f3b214e31f24b635bc45651cf7004da4718cb0b8c844d27836153711da3d/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string28 = /9120da326f6d13c492ca42da217b25a24515ca0d2f468acde8ddb5d5417c6652/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string29 = /921157808497e5fe57f27fdb490be391f0f28bacffdb8cb9ed233bc3929b85a3/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string30 = /9c8c6832651517a7f48e8cf246721ee80be13e61222f12ff5876f7cfb92a6308/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string31 = /a77a13a5a04bd0753a883fbefab58bc0504cd151303e285bb3799d6c38196a30/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string32 = /a87fea89545bb209dcc98edfe23e5171def343793d956308ef1c9b5c1e477990/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string33 = /acb7923ed1efb328d724977f2507a7a721a6c7cf630a3b37a9f4d7a3a2c7010c/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string34 = /ad97557e81bf680c9c796b2673a34562a0f80cb27b88bf53fe20a9a281723e07/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string35 = /affa24f6e1fd339093365bfce238b94ec6948d4d1c401fc7dffc4921e9da0187/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string36 = /b3f9b4b2534e4e7cf71b72d5f37b0745e0f6eda8ecc81c1e4139319f4cd56b34/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string37 = /b670fbc71576142dedbc158f3b6b9e0a5889068759a13b2c8bdc14d1b85074a8/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string38 = /b9946bcbb56b9088f6d5ab8660665ea8f80c5f3d08df6e4531362653d07de2c9/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string39 = /bb8a907ebbe611f271b35d461b15ccb8e90e36567e9963ea9a64ba4fe3d7d1bc/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string40 = /be9b23c9cf6731a8ae3d288871d277e64ca0caa5020433c4516b58e10f5e641f/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string41 = /brutespray\s\-/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string42 = /brutespray\.exe/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string43 = /brutespray\.go/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string44 = /brutespray\/brute/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string45 = /brutespray\-output/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string46 = /c2db7182d606ef3d00a40360e62f16a47aea5d39872bb5bab4b115d4da864394/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string47 = /d16d7eaa9f5abcafb83da10a9b729f7c9b090bf209fd7b9ea820ed942c328d60/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string48 = /d75a64a4ef72a0c5bbdf8703bc5be50ee1569bad06a77a59e18a525c80c27a99/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string49 = /dbc10feaef6ccaf49866bac8d3ddc48729e7163639d6e0fcdad9e8f90178896b/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string50 = /dc86081b57b7809bfd3df4c8ed664ca0a786a239bdb522ea129f66571f4fd992/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string51 = /df110ed12c12b69bd7791fccb00ecb9ef8eb38f694fb8252cb9d55590362d8fc/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string52 = /e273485e4f1382b7848b6c263cf0ce9e37aa783e9e781630aaa50daffea5aeb2/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string53 = /e2964ea4bc4e439e55f46ed309904e9592145858076d65363a2bbbab0bd608cc/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string54 = /e5a991c13b8ba7bd2e435dec2682cd31de0013b3455c18e3883608e75363de3b/ nocase ascii wide
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string55 = /x90skysn3k\/brutespray/ nocase ascii wide

    condition:
        any of them
}
