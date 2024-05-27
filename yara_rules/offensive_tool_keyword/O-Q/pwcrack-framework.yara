rule pwcrack_framework
{
    meta:
        description = "Detection patterns for the tool 'pwcrack-framework' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pwcrack-framework"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string1 = /\spwcrack\-framework/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string2 = /\/hashcrack_com\.rb/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string3 = /\/hashcracking\.rb/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string4 = /\/md5cracker\.rb/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string5 = /\/mobaxterm\.rb/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string6 = /\/pwcrack\sbanner/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string7 = /\/pwcrack\-framework\.git/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string8 = /\/pwcrack\-framework\// nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string9 = /12949a43a532f0a6ed86b7a877df767050ffa81e3afa47241fbf61cbec5e58f9/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string10 = /162bc32dbc28b62c3a6bcaa33b83f4a99ca60453b229d35d0ae5bc1e80b98673/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string11 = /36922dd433801687ef428a64f1db8195d4efa8112cd7629b283476bce58e1d30/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string12 = /3aaa5fde51d080a80e911b350db316669db2ca264b1b6f55cdac91d1ad5267bf/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string13 = /42a1be47225d778ad55b6acccfe487239ddc6ee0cc5b5471038568dd2910811f/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string14 = /4c22a00104b52b74247f83b5c50ca09d5e9ed2db3d7d1843fe75fc283d50ffb1/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string15 = /54fa00769c5dfc41a26767786517a7b99a7551b16b5589cf3d5287ae1def8534/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string16 = /561c5f3163f3e6864d547c4412339872841fd9b5d365f10a0d95d2bb366b8396/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string17 = /58297eb7cad8589399f7b0bc92d61c144ee05786dfc06f527826965ae4062f99/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string18 = /65b73f44795c9d8a7ac35a5d730787d72c2ceaa15ff0a8788038bee7b56edf48/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string19 = /6babb664a4c688234f19f258d7a4de2ffd2b8eb51a9ae6c35ea0bee20d214453/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string20 = /72147820461101ca9687ef5177cafad482953946d1b93c54c1cfc69a953496ae/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string21 = /96a355ad3176a2753b403b71f5e39c36dfb0489b621822f7da459519ed6bc4be/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string22 = /a45833f0ee2541c060b8154389fdca5cf5bd19f460352eae83c4fbe024edc803/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string23 = /a50f337900d9adf19bfda21fa5d89c5b1525cbb96c1cddb9443e62d56f5a8e5b/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string24 = /ab86676468036b6f915ffcefd6e05aa56bf02459a383c46dff095d5852a996e2/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string25 = /b3eba9d048c4b7cd8e01d81baa74daf0eb097f584c946ac0ab10ba08de1a8d7b/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string26 = /c07272b6a537d203f886cd195e1ad2def64123c52c61a5d0652b26f1b288553d/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string27 = /d33f6e8b7b07e293f431cb39fb4463d854500921ee23fd661143a5c01785417b/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string28 = /d5b211c3a68fdd0231c3f6aa72dc980b8481e47fca6ce40605021d3e6222d7c5/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string29 = /e3126e7a17ffcf6e659b3b603134067a47769e74244032cb6e23a5532913291c/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string30 = /e4b84fd04cf067c5bdcab91f85599ab53671d9eda16a60590886824b8b5e7cab/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string31 = /e56bee79647fdae60a15c1dc283a990121cd5f387900929ca044dff8e0e2b427/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string32 = /e6e97a564798df361f372645253f7601dbfd3c762c4143326df41a574bc97d22/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string33 = /e9073493a75df11850c5f3e6738b108c831ed0346bd6b9c5e5cd18e4bd4d645e/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string34 = /f7dc6083af1eac05ea39386513b98d2942134e6e2c7e236e070c71d6469650a7/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string35 = /fde22ab519e821b78566ad716fe961d55cec7a447be32e5405f46d10f2e9b233/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string36 = /fe2952ae150d2a92e6ef03f68022dc10a792fb8c3e44a46cf2ce1e095e45b9d4/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string37 = /http\:\/\/hashcrack\.com/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string38 = /http\:\/\/hashtoolkit\.com/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string39 = /http\:\/\/md5\.80p\.cn/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string40 = /http\:\/\/md5\.gongjuji\.net/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string41 = /http\:\/\/md5\.gromweb\.com/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string42 = /http\:\/\/md5\.my\-addr\.com/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string43 = /http\:\/\/md5\.tellyou\.top/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string44 = /http\:\/\/rainbowtables\.it64\.com/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string45 = /http\:\/\/ttmd5\.com/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string46 = /http\:\/\/www\.chamd5\.org\// nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string47 = /http\:\/\/www\.dmd5\.com/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string48 = /http\:\/\/www\.md5cracker\.com/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string49 = /http\:\/\/xmd5\.com/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string50 = /https\:\/\/cmd5\.la\// nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string51 = /https\:\/\/cracker\.okx\.ch/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string52 = /https\:\/\/dehash\.me/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string53 = /https\:\/\/hashcracking\.ru/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string54 = /https\:\/\/hashes\.com/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string55 = /https\:\/\/lea\.kz/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string56 = /https\:\/\/md5\.navisec\.it/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string57 = /https\:\/\/md5decrypt\.net/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string58 = /https\:\/\/passwordrecovery\.io/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string59 = /https\:\/\/www\.hashkill\.com/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string60 = /https\:\/\/www\.somd5\.com/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string61 = /L\-codes\/pwcrack\-framework/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string62 = /pwcrack\sinitdb/ nocase ascii wide
        // Description: Password Crack Framework
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string63 = /pwcrack\supdatedb/ nocase ascii wide

    condition:
        any of them
}
