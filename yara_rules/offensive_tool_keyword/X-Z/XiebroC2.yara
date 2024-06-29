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
        // Reference: https://github.com/INotGreen/Xiebro-Plugins
        $string7 = /\\Plugins\\Resources\\WindowsFormsApp1\.exe/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string8 = /\\TeamServer_win\.exe/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string9 = /\\XiebroC2\-main/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string10 = /16091e51ca4fcdf374a839ff3b850638918915b5d04c032fffec402286daf4cb/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/Xiebro-Plugins
        $string11 = /38AF011B\-95F8\-4F42\-B4B9\-B1AEE328A583/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string12 = /39e848ddc5b27f5ff9be14dc925a8d2e3da39623fa02367a09a3f36732d55300/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/Xiebro-Plugins
        $string13 = /4B37C8BF\-B1C1\-4025\-93C6\-C3B501CBB152/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string14 = /529b3883e56855e121fb77dc6254cf1280964b9323c71f631068c3ac6be9c4cb/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string15 = /5338267c8ef94a98f32ff42a23862c5dd42a3c19a7ad3d250ff1a9f263c17974/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string16 = /5e58cd83a2f4613303713489e819e69a42109141e3c998e21bf25906b45eeb30/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string17 = /77873f1f629ff4f8635b50544849c7904db358ee87733f42f3bcb19c87da2eab/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string18 = /7b8f9e66368aa0606e480ca7b8c62cbbd2fc9ff726630f46ed45aa45e7786e62/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string19 = /7bd1a6f777a6e86907b0b3bf24cf013bb419a4fe24b9e0b2af23fce70d823c29/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string20 = /7d251c4c6b137a24214a9f58a0b88f2eedad23d0d62050f36a567b78cb2ef497/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/Xiebro-Plugins
        $string21 = /7f3c414abe39b6e9ab37c48d5962f421ea91971a21f3eb1a9ff1789fafc6649e/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/Xiebro-Plugins
        $string22 = /835b7b956f39cff5bb6e31a4fb06ba65615ae809e249b8161126e750b9fe1aae/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string23 = /8785484adcc6ef562248e172e23ebb36ab0b7b500281a56230bb102295586897/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/Xiebro-Plugins
        $string24 = /AddMenuItemA\(\"Grab\sbrowser\sPasswords\"/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/Xiebro-Plugins
        $string25 = /AddMenuItemA\(\"Pentest\"/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string26 = /b4239ef8e8962d393767152c150f17bc5cf0527d6fed52d489b444f46402650a/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string27 = /b92a810f34ccdcaf783067a0534be97ee2f51561ce8a07a948c887edb234dda4/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string28 = /bbafc8c3db7a42d1419f9c741f6508da43325f3993202d8955b2f9e0d2f971a9/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/Xiebro-Plugins
        $string29 = /bc051b7ae14e30935c4cc0090a944f420fa69cbcf66469038af5a306030b9007/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/Xiebro-Plugins
        $string30 = /BypassUAC\-ETV\.exe/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string31 = /c4bb5669fe12e106bd6bb7a0fde51cf6e90d73bbd6e4143df40eb53d2f7da776/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/Xiebro-Plugins
        $string32 = /c79e051bb46302d29235045e7ce05e9806e52f7fdc0249a9593cd8fa01e11c35/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string33 = /chmod\s\+x\sXiebroC2MAc/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/Xiebro-Plugins
        $string34 = /Convert\-NetToLua\s\-infile\s/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/Xiebro-Plugins
        $string35 = /Convert\-NetToLua\.ps1/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string36 = /d9dd9d8ef1406c7ad002253fc6e65d035037267640f44338e9468e219f95bf3b/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/Xiebro-Plugins
        $string37 = /f2f43c5e7b7af02097483d4ea3ccd1bf1cf2b6a558e334a3c4821522a5214b73/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string38 = /fd0c892807df56578a3beb415d800c765873ed72ab256f5cffdb5cccd086fd27/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string39 = /greentm372\@gmail\.com/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/Xiebro-Plugins
        $string40 = /InlineAssembly\(\"Plugins\\\\Scheduled\.exe/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string41 = /INotGreen\/XiebroC2/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string42 = /set\shttps_proxy\=http\:\/\/127\.0\.0\.1\:9999/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/Xiebro-Plugins
        $string43 = /set\shttps_proxy\=http\:\/\/127\.0\.0\.1\:9999/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/Xiebro-Plugins
        $string44 = /SharpKatz\.exe/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string45 = /Teamserver\.exe\s\-c\sprofile\.json/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string46 = /WINEDEBUG\=\-all\swine\sXiebroC2MAc/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string47 = /XiebroC2\-main\.zip/ nocase ascii wide
        // Description: Command and control server - multi-person collaborative penetration testing graphical framework
        // Reference: https://github.com/INotGreen/XiebroC2
        $string48 = /XiebroC2\-v.{0,1000}\.7z/ nocase ascii wide

    condition:
        any of them
}
