rule dnspot
{
    meta:
        description = "Detection patterns for the tool 'dnspot' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnspot"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string1 = /\/dnspot\.git/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string2 = /\/releases\/download\/v0\.1\.0\/dnspot\-/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string3 = /101ce1b9d0a8f8870b287bdc3308e443d3995cec57162678d83772df947a5ad4/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string4 = /121a8382a9b50c51ffe0269efc4db9fafee9cb7dc1afe5ea5318b2d2439b22c7/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string5 = /1515c3b59422ffaaa8ca8eea53ae86a27a2c107972aa84e6b9cca68c7c9d53a1/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string6 = /1f607d81f474d120730e81149d0597ad822da8fe41eacacc7dac394d0a2df4d1/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string7 = /2329a9ff31f85b197f5d1ce5af29167de3027b0b80e786080ab2a7bd046b8dd9/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string8 = /3874c97fddb57971c35e02b68b74709f05ed396c19dceacadf4d9432c5a0206f/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string9 = /3a2d28a6ff81e99af6bbeb0d0087866389c0177104b8e657e302c20ae4f6381c/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string10 = /3dc7e0f43e9ebe086c137fa1af3bf410c3d566f1edbceeea7ea5e19d1f9ab5b8/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string11 = /4a3192bb30ab0b91e3909e2b64b22ea7a262199c5edf5d2f54946dc5212bc7c5/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string12 = /5154b1146c48faca26e0276ce7fecb023e5d3d2b62d3e2157df51650ba834e23/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string13 = /5193483fa2796f8c87502eb8efbd9f462dfaa8ea94e9ffdd28bfd2b569f8df54/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string14 = /51ae11608f904fb4fe9bc6ff63dacd0e318921b2aefcb81481106a1073205ae8/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string15 = /526feda402303812eac1b6663f2de7deac3bb433fcb9855625ff7d8201245416/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string16 = /542c779d785acb08e773a28f3de3c51c64ebbb2bbea0bd3ff70dc87f830add68/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string17 = /5506149199922b7560a4f6d669fb7f7b61f77668c5f8cb5a81128d0bdc1a2b2f/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string18 = /55cb93078b605122dcef64a6680ca4dd2217fc0668704b0363bb227811b180a3/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string19 = /59eb20e71e9284537d2626e19a2c12a633c7568d115d939e95cfc51ee1f53c61/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string20 = /5a8f375901afcfe1a4152984d4cb6c1d6c0084964fe76b689bd7bdef6a83b959/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string21 = /5b71bad75d676d0520ed50ea05534dcfb748c19b68232adb5c5f3d9035814de6/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string22 = /5slcifus86ojqs51ubctih0p35izi3x6ynyo2q2pnqs7syvnqa/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string23 = /608faa1b8a5144d7d610d78a4b4f8eb834c4c786cabc52fe8cabaf95df3ed02e/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string24 = /60997a4c7f91341633eeaedb0f9316d0ac734a03255b11da128bbc7ac7c3a102/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string25 = /6783b4ec3c93421324cf6b7835994545baf29c5b1341a26a565e57af77ba965a/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string26 = /698fc52837dab69301c96949a3514845f16a6b3c2a8faf14b08ce80c4c575f2e/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string27 = /6c984cacd4950905c61a2c6d962a8a9e63f40d0d9d834b26f453296d25356ce8/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string28 = /6ec25122b3ffbf7f7dfcc44141b5e8df729a9bdde5ae169275d8fe75b0ea486f/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string29 = /7212755666c85ed4416a5ed2f317777d7fbf6cb65f42041949272fd3518a7566/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string30 = /780bc4923a0f141eccf843b710cedc117075b51562bce79289fbd43b8335a0e9/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string31 = /87998922dfe61e2c69bd8bd483f81668d961843d9afb491f0dc48694e19b4002/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string32 = /8c78f5d5b2668b66f9c306a1c1860d64489582fc757a96f6a9e9a8800f4ec11d/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string33 = /8c96263d8ba4427c67bef9f7fc7bc57c04c6fb61849a19599cc52503fd701daa/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string34 = /8efa930aaaf5c4db5ff39afaf5a1ef5a396a4257841ccdfcb66f3a2f1637db6d/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string35 = /9092d0cccf0f55b0e680d64f23e6c2cc6e406ab4e05d54aeafe73e9a9943b739/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string36 = /929ca5f7728d5b18bdb5fae5862b9ad565e1aab9fe38c416760caf2b6867eefd/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string37 = /a19fbec8a7ecca1ba56daec33727923e722576d5c7fcbc92ff86149ff4f2d425/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string38 = /ac573a39363e52c1f32be7f75d8eeffae5bf21689b6f07804e1f5c667c40f6be/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string39 = /ad710c24d6097ad20bf1bbda621f02d5b7410730ab4b08395cee96276f5f8bf7/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string40 = /afc4be6010ca93ce9fbd373bb9795be61db66b236201236d7193934970926b6c/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string41 = /b49250e1629e9241310ea0b4db1651be12ad0013e605bb1b5c57de826025ae41/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string42 = /b5122cb03f986f687d1baae60cf8fb683ea112dfddb6589f9713f964edbabef0/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string43 = /b7204f1550e45bc13a6d896883bee7ac7a5a80442c77a86a6a33d74e6e69df73/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string44 = /bc10e4d6dd01c0d941795e6084bac19a8ce38c5b581523845a748e56579cce00/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string45 = /c1cc14efcd2df072977c1371065807c3d2e4c6a576db89230b5c19e0ef00040d/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string46 = /c366f4e24e27994b39a860e046498ebebf9f9633f05a12dbd8ce65eed2a9f6f0/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string47 = /c9477106a63804fc0fc18aec7db98e372faac1cf192d976211b9867a22354c85/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string48 = /ca0b9b718173dbd056497bf66d6ef7bd81ca4a52bda882e64b4d418c88121d7e/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string49 = /ca8066d0eb20a83470e87bb583f11a864146ea958321dae51c93b2272a9b5922/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string50 = /cd92c3c752202b095097b1f2236ed579c473e8da86b6c2928dd0690cee42ab33/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string51 = /d135953447b64497e94928624cc0d3b6e42f32673a4cd53215f0ae6861129f99/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string52 = /d14078723dbc8e252596c6528cee47eb889bf38f29bc69d04e23634ece8c2b2d/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string53 = /d2b3eeb6f1b53e1abcf5d2bd58a1708466a9d6414e5b7c0ad14d89566e7b6c7a/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string54 = /dnspot\-agent\-cli\-/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string55 = /dnspot\-server\-cli\-/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string56 = /dnspot\-server\-tui\-/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string57 = /e5978b950fec8996d30b98d75e89c1b58fb9a38aa450af8c63ca2f8c23025678/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string58 = /ea9786bf97f56c75668dc7cc037a7d5661d413741ffce35073a0f2edae5d3066/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string59 = /ec212e0be2629efd3fe6c0d1085d4d42f1245a30ff2dbe97fe708cdbdd55879c/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string60 = /ec2b6024e73498b915399094e92d9976dfb2f1fbe07e476d67f36edbfb9b8532/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string61 = /ed8071b56d96c49d5c8b0500eb9a3a946e9d60846190ef8f33de873d23d0824e/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string62 = /eg0he2d9cr3hpvt3z76trvkl7n2bivgscpwd5xfgn0oqgqlq00/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string63 = /f23950926273d8ee262e32edf0325618322cc22a9fbaf300d5692e48c5fdd18c/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string64 = /f5b50fa27059710ba9910381fd2fd8dc9c95f2e519e0079bdd1ce34794f60d5c/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string65 = /f8f187ad240a6f23403c387c47ac1b3ce77301ff4ea1b3dbd639b76d65ca54ac/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string66 = /f982b52ea6ec43f90e7adbb3a06ae09d9b775dca306962de90f91121d3da2ac2/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string67 = /ffe9b626de7112df222bc99cbdecd1f321533dc08e32d2e19cea9642bbb0c4f7/ nocase ascii wide
        // Description: End-to-end Encrypted DNS Tunnelling and C2 framework
        // Reference: https://github.com/mosajjal/dnspot
        $string68 = /mosajjal\/dnspot/ nocase ascii wide

    condition:
        any of them
}
