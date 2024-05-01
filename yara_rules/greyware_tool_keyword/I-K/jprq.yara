rule jprq
{
    meta:
        description = "Detection patterns for the tool 'jprq' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "jprq"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string1 = /\sjprq\-windows\-386\.exe/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string2 = /\sjprq\-windows\-amd64\.exe/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string3 = /\/etc\/letsencrypt\/live\/jprq\.site\// nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string4 = /\/jprq\.git/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string5 = /\/jprq\.log/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string6 = /\/jprq\.service/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string7 = /\/jprq\/server\/.{0,1000}\.go/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string8 = /\/jprq\-darwin\-arm64/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string9 = /\/jprq\-linux\-386/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string10 = /\/jprq\-linux\-arm64/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string11 = /\/jprq\-windows\-386\.exe/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string12 = /\/jprq\-windows\-amd64\.exe/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string13 = /\/root\/jprq\-server/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string14 = /\/usr\/local\/bin\/jprq/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string15 = /\/var\/log\/jprq\// nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string16 = /\\jprq\-windows\-386\.exe/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string17 = /\\jprq\-windows\-amd64\.exe/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string18 = /\>jprq\s\-\sjoin\spublic\srouter/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string19 = /01713b6ae56ab0f1faf7834f29c22fb36c41bef9c6cf2b702dc3f617513c3be6/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string20 = /0cfa716d39fc90ed0c4db1bd68f1b4b791f26e5fab4003ae9b816d1f7d68d208/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string21 = /0d05bed47cc1579a068f83123a502c59d447b20a5318c1d70ffb7a0b638a7aff/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string22 = /1a1b2883ad2c55fe3a1d4544bc1401e92a0b98148d85f6e5fdaa54154ba5a2e8/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string23 = /1b41fb4be93b92548f9e5419fae45b76592a5b6ab0c5d42930f6824686225f3c/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string24 = /1e68cb8928288f31a3f1b7fc867f79f56912c289f93a3dffd962fea895fb8f12/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string25 = /2ed85cb524b3d21a29ae39ad50874d1cf8546d2dfedb931b9fcf76cc4e0e7cf0/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string26 = /31fb5154969f2729699b04a7ea6202ad59dabb1e36eb5f8f9b1159e3775e267f/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string27 = /3984e827963ca5f0925404d02526b0c12956f4d04a64853226e54a2f9333bf04/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string28 = /3eaa14907c96c3a261cce8f5379fa8ecab9911cc2f3711b4b08b8d382a7ee772/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string29 = /4796c4183abeeb96966e3eb03493345cd7e148688e9fe5613c5bda26692063b7/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string30 = /51e63f127dfc4804bec4dc1e5bc19034d50953c246417203b95ddba89bbfe082/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string31 = /5a19b174e1c46c7f3591c79dc5264d43bb68c9537393a8cecd6269567b821778/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string32 = /6c3dc714596f1b78c4921bb8b25f073bdc95a8bca363f070b4e5e34c4b2a34ac/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string33 = /73314bd200038dc11b2a008f9d90164565d15744724a5ea9a0750823a8d0d73b/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string34 = /7d367e348e24f197222c639324ce56bea8d2b2cd39c88f8df390e1b5af90942b/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string35 = /8e63f8fb62f2dd2f310bf619ab65c97d5dd1835d97cced5eb8cebddd293d2d06/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string36 = /905bda9ca65d9b7f6151de763a7c3ce2dd15a69b8410d89b04dd5bb68d17dece/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string37 = /9e3476f783250e1fd848c17fb9d5a6c32e151ff1382bcde09a0ac903dea8a16f/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string38 = /a56d443310f333dae0b4900ca18d0f903f5076369ae4053c035d9c39d76f59b2/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string39 = /acd19845a6484eee65db6f925b1d0244300831d4d5a37d147cc61e7e8c56775b/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string40 = /azimjohn\/jprq/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string41 = /b44c1910df6b24847b75712e9f183d5fd9119e2e4dfdc15eeecb5e7159e4530a/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string42 = /bdca5844eac154b94bbdd1b51e68f7d4e45a560fa13c7ce0a227646b0091982a/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string43 = /bf356e9c87e06eddfe9c5c476742bbc9cf26405631296f03c8f57f91afbb5247/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string44 = /de10b700cffb64956f55e044a9ce830d9b775af10560b54f21b2fc125c801618/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string45 = /e749b296484dbb4329fc0e4dff5fe963ddc7ff3450042ce267fdd1b5abcd2fdb/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string46 = /f11f0d5b7f14d4751f40b9c2c92928dfdbe0d055981e140ba0a5d75ecfe72e10/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string47 = /fc621d5952a8fb61bfc73e197db64d87f35d1c12550b7bf6160bc78f6d61e44f/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string48 = /github\.com.{0,1000}\/jprq\/releases\/download\// nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string49 = /https\:\/\/aur\.archlinux\.org\/jprq\.git/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string50 = /https\:\/\/jprq\.io\/auth/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string51 = /https\:\/\/jprq\.io\/install\.sh/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string52 = /JPRQ\s\-\sThe\sTunneling\sService/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string53 = /jprq\sis\ssuccessfully\sinstalled/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string54 = /JPRQ_DOMAIN\=/ nocase ascii wide
        // Description: expose TCP protocols such as HTTP - SSH etc. Any server!
        // Reference: https://github.com/azimjohn/jprq
        $string55 = /MIIEpQIBAAKCAQEAuIGT1C2uPwb62IT\/5IJdFioVAB\/r3Pa885n4z\+xEtGIm6XmD/ nocase ascii wide

    condition:
        any of them
}
