rule XiebroC2
{
    meta:
        description = "Detection patterns for the tool 'XiebroC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "XiebroC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string1 = /\/TeamServer_linux\s/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string2 = /\/TeamServer_win\.exe/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string3 = /\/XiebroC2\.git/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string4 = /\/XiebroC2\/releases\/download\// nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string5 = /\[\+\]\sRootKit\sloaded\ssuccessfully\!/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string6 = /\[\+\]\sShellcode\sinjected\,\swaiting\s60s\sfor\sthe\shook\sto\sbe\scalled/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string7 = /\\TeamServer_win\.exe/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string8 = /\\XiebroC2\-main/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string9 = /16091e51ca4fcdf374a839ff3b850638918915b5d04c032fffec402286daf4cb/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string10 = /39e848ddc5b27f5ff9be14dc925a8d2e3da39623fa02367a09a3f36732d55300/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string11 = /529b3883e56855e121fb77dc6254cf1280964b9323c71f631068c3ac6be9c4cb/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string12 = /5338267c8ef94a98f32ff42a23862c5dd42a3c19a7ad3d250ff1a9f263c17974/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string13 = /5e58cd83a2f4613303713489e819e69a42109141e3c998e21bf25906b45eeb30/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string14 = /77873f1f629ff4f8635b50544849c7904db358ee87733f42f3bcb19c87da2eab/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string15 = /7b8f9e66368aa0606e480ca7b8c62cbbd2fc9ff726630f46ed45aa45e7786e62/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string16 = /7bd1a6f777a6e86907b0b3bf24cf013bb419a4fe24b9e0b2af23fce70d823c29/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string17 = /7d251c4c6b137a24214a9f58a0b88f2eedad23d0d62050f36a567b78cb2ef497/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string18 = /8785484adcc6ef562248e172e23ebb36ab0b7b500281a56230bb102295586897/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string19 = /b4239ef8e8962d393767152c150f17bc5cf0527d6fed52d489b444f46402650a/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string20 = /b92a810f34ccdcaf783067a0534be97ee2f51561ce8a07a948c887edb234dda4/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string21 = /bbafc8c3db7a42d1419f9c741f6508da43325f3993202d8955b2f9e0d2f971a9/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string22 = /c4bb5669fe12e106bd6bb7a0fde51cf6e90d73bbd6e4143df40eb53d2f7da776/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string23 = /chmod\s\+x\sXiebroC2MAc/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string24 = /d9dd9d8ef1406c7ad002253fc6e65d035037267640f44338e9468e219f95bf3b/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string25 = /fd0c892807df56578a3beb415d800c765873ed72ab256f5cffdb5cccd086fd27/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string26 = /greentm372\@gmail\.com/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string27 = /INotGreen\/XiebroC2/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string28 = /set\shttps_proxy\=http\:\/\/127\.0\.0\.1\:9999/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string29 = /Teamserver\.exe\s\-c\sprofile\.json/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string30 = /WINEDEBUG\=\-all\swine\sXiebroC2MAc/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string31 = /XiebroC2\-main\.zip/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string32 = /XiebroC2\-v.{0,1000}\.7z/ nocase ascii wide

    condition:
        any of them
}
