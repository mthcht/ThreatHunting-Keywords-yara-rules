rule Group3r
{
    meta:
        description = "Detection patterns for the tool 'Group3r' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Group3r"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string1 = /\/c\slol\sfuck\sthis/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string2 = /\/Group3r\.git/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string3 = /\/Group3r\/releases\/download\// nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string4 = /\/LibSnaffle/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string5 = /\\Group3r\.cs/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string6 = /\\group3r\.log/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string7 = /\\Group3r\.sln/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string8 = /\\LibSnaffle/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string9 = /\\passwords\.doc/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string10 = /\\passwords\.docx/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string11 = /\\passwords\.txt/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string12 = /\\passwords\.xls/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string13 = /\\passwords\.xlsx/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string14 = /\>Group3r\</ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string15 = /006ad795269259c08e5b8e1816e05a4bbb52c97997ff238180afbc53365d3428/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string16 = /10accf5038dd9a3353d50e63d208c684ddfe8df4d06b33602fada0f44a739039/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string17 = /14442756c9e9124e5f854b6c24d1176ee2f393732fc52a9df45486aef98abbc5/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string18 = /1be348a72f9fc11fe85f58866d0deeaf3798b300130493da6907f9d1213a9328/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string19 = /2155d44b48c8495225b37a0ebdc72cfecfff3fa95cedf04205e416e4ef36c808/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string20 = /220fc01ba29a57c350860f685caf64d84175f214dd84a43cc16c577fa53c9308/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string21 = /290d030d8061bad86860efb7b4ae29b7a9359cfb8b33fc8e5cdb3fad3c645f8e/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string22 = /29487e77a2dfcc7b58d901ed412c86d7b99569f640dc3b8a81a611bbf8f7c1d3/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string23 = /2ae02fc1566cb4e055e56ff446f6de80fcaf953da0fcad0ed93b6454b9fba4f1/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string24 = /2b3c71c9430092f6b3d0c8675d99eee23b80410612971e902245176baf46c9cb/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string25 = /38698c9ebb4f24b1b11d2b5c023c72b24c1e68de5bd2bc04384e85a1467e0a00/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string26 = /3d43ec6d4f223272bf31597619e5799de07eaba84fd4c5a57f8344010e0581a0/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string27 = /427a990d8ee64c640faa8e1be48637ef64ec300615686d4bf212503c7926e2d4/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string28 = /48305b78df432d4e3b15a32a516fab118add29b2c12a49806745ea92f2a98b1b/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string29 = /4ad3b9a888e8b5338f81b44637feb93f929d8314992fc9b9b6566def8a6c59f9/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string30 = /526a14c1b561a020b7544843883117037131175b38109000b4848ea1c7963bf4/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string31 = /55079c4485a5c2df00c8e1c2f068cac31ffe13f95f0f7a822921c582f1dbeda5/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string32 = /553282d19684e327d410ace6c54aa6cbdecba1eb2e67ecbae0e44d46426eca82/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string33 = /56a26ec84de85315d3123471e8b231d593d2bcb0539528c51f47f23a1db2f5dd/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string34 = /56e1e8e6e7add2849ee78462abb30ea40c23d6a1e06036473f82d214bafa9f9a/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string35 = /5cb5931045705f9c78923247204bbca0f6b7bc4825af11bb053b7e4297e23f8d/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string36 = /601cbe74d7aed23f52bae7d326f08b86665c167b3d14fedfa545efb5a6e56d83/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string37 = /6168269eab4621cee6694242ca0d9e5c006f42467751b1a1b0dc70228894b56d/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string38 = /6cdd4782f5551b4f3005974733eab16d0db8b2b3e385437af8f0791b06d7e431/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string39 = /706dbc3ea14dde772f2c6d4c85e20e4912dc2047c6dd2b00e2f995f9423518fb/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string40 = /70eab06c1a1f041d6e3d65e83623ba9097855ec1e8330d1bfbe4153d23dd4989/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string41 = /7985cfa2c992f22675afceef7bc9cf8e0d1fda7ce07a46eed77e390cc3157243/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string42 = /8407636b032bed867e4fe3f13d31292e55de7183947c5c2b6c8fe984231f76c8/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string43 = /840783103a165accdcc4f1ce1e2239edbe4491cf0599700827bd773499c9d17b/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string44 = /845cd5a8ab75cc81e6048537fb516fb92e50b586d67927d7be9fc10a620d7025/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string45 = /858d9587a7b7bd18b9f1b3bafc61084475898fc185ef1e2fecdf0777e58e1531/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string46 = /868A6C76\-C903\-4A94\-96FD\-A2C6BA75691C/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string47 = /968cfebad222f175df52b968f5479b7ac8f06a7bde32a47d2bada49ca09cad70/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string48 = /96c9648216ca09c9c7980f414eff4095815123f0b8404caed883c361ff77b85f/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string49 = /a236a082af48fe2e9a9a0ca59bfc1804e67b1c31755d26cbac7e6ca167a66fe4/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string50 = /a512642f7af44ee8946f171b8921997ec271bf1c9f1e747067a6dc7b192d4ecd/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string51 = /a83a41e188cc050f6cb63c7a45855f1095b5db1bbbc26a2cc41696f8be8be2d0/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string52 = /a8bb914637ae760a57ab1ea6f00636348371f4bff4ddae20cc14b533ec6d9e6b/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string53 = /b1906ee99c71103357472e4ec7710f973a3283178611af0b7c4b6e78b0687639/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string54 = /b2d5cf34fa343ceb5f73db00d1b647722e871c4489d917e80db438c7b926d45a/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string55 = /b5309c785e75feec7be157b0965444e2b2b0d4c592769f20589a3218f32151c0/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string56 = /b5e916565fc5a539fd8e96436a17c57e38fbec58d8bc8a450596fd03c343a774/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string57 = /b77770a81d59239b2ada0f633c563cca30e3bf3e112a8545aee13185265c6324/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string58 = /bc7f0c671c1035f9af93b7b657005fbc4807deef8071bc58bf310f821cf67944/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string59 = /bd6bd65ef2fa8d4d1793a31b863d2245eeb1e0ac361b84594a25236e43ff4d8c/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string60 = /bf64fa06291007eab0b142b91ee7ce9ab9657ddda240d98c141a0555da90cb4a/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string61 = /c034271dfb3dc754e0b24874fde53c0657087b3832f97c405d2a59f0fc4f8193/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string62 = /c69727332807589ac1ed83cb794a36a98bf754d73d56063ba6a25bbeee71d6b1/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string63 = /c89d8852d0a35fe9bf532fa3da805f715527e3e38065db0cf5da7f993531f87f/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string64 = /c8b7754a7e593daafe1fc7804731fca139ace13fdcf3842ceada5d97f0a358cf/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string65 = /c909fbdc6b6254554995cef9878eb4982edaa05f545236ad78c1eb34f68020fc/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string66 = /c98676e955d513ce879f60ab157673e4d22c273b4f940c16258fa0bfd8729ffd/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string67 = /caa6677a1abcce4018d5e5872d19f134ebdf27ad34c6b9a7356454342db37624/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string68 = /CAA7AB97\-F83B\-432C\-8F9C\-C5F1530F59F7/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string69 = /ccd3694e0110b8416c04ad17e4d3f1e5fc9b724e29c942a70f3ff2283c4f8a79/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string70 = /d329cca0959dea29eaba648c72467bc41d7b8560061acf377124c208224d035d/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string71 = /d46ed22a1d5e5224bf6a5709526d8ba4cd8fdfc6332199d80d0d8aa9d0d725e2/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string72 = /d6f5f4e0aa4e8a9b34887f008ff0882a4f3738d35c9df9c023512d1d5f6d9871/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string73 = /d7235f7b09d231562a5bb697e521c635343eafc044f92f11c541ea89d04ae7c4/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string74 = /dda3dda6bca9be9945ccf838141b570f08b0763ff0eb74c1b17ccce22c9ceffb/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string75 = /defc2b9e497d0fc59383dae3ae2bba2780be242d862ab6d44a5f7e0797ed9e6a/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string76 = /e0527306862820f76f0d843e93c1a19925697a7f2377b41377cbe99031549920/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string77 = /EnumerateDomainGpo/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string78 = /f09a777ff1bb221184f60cea61e092b51b096f25cfe5650d84516c09013233a6/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string79 = /f0d60a0c31f6aaa68c096553a8b983f2c9c78c96022118d1e1066012ec9c3268/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string80 = /f80044aa9f0d7d7f10b8655ca33b573f3c62983a74d5399e869653b323664066/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string81 = /fd228d94224c9daa219509f1f2ef6b365b070ebcf0f7337df5655a9d58fcc6d2/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string82 = /Group3r\.cs/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string83 = /Group3r\.exe/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string84 = /Group3r\/Group3r/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string85 = /Group3r\/Group3r/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string86 = /https\:\/\/crack\.sh\/get\-cracking\// nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string87 = /LibSnaffle\.ActiveDirectory/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string88 = /LibSnaffle\.ActiveDirectory/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string89 = /LibSnaffle\.FileDiscovery/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string90 = /Qd7SkrRYaGMvOlLz1Qyk3A/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string91 = /VPe\/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE/ nocase ascii wide

    condition:
        any of them
}
