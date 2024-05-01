rule go_http_tunnel
{
    meta:
        description = "Detection patterns for the tool 'go-http-tunnel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "go-http-tunnel"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string1 = /\stunneld\.service/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string2 = /\/\.tunneld\/.{0,1000}\.key/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string3 = /\/go\-http\-tunnel\.git\.git/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string4 = /\/go\-http\-tunnel\/cmd\// nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string5 = /\/tunneld\.service/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string6 = /03cbb2a21105c9aae4fb499ad8fb4898d6c87c7d3a3071eae601bdae8bad19ab/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string7 = /0a08cac081d32713c5aaa00b04424dcdf2ffcaa7b58620eebc9ee17b5d25ebbf/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string8 = /0cba4351414f3da3355bc9ab73052e0d36d6f18e513047650dad956fb6344285/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string9 = /0faad61745a8c559756165ec4bf749c7ee334b815b750dbdc671af2283805739/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string10 = /1433542e6c771cd59c491558e482ebbc7d40bbaf86190379bb4236067b21d805/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string11 = /14d18d34c262664246cc1eb46dfe1159fce9b5d0b14d6ba013f08d1d55a6eeb6/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string12 = /2c183c4c53ddb0419f401cf690f16ccbeefc829f09fafca2a19700665c322cbc/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string13 = /341e6c79cb6383b166d0f21f77f88735b340195dce8945bf9ff05a3cda1cb9a0/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string14 = /3daf819f691c66a2216bc047349e5d6ed252aa1393c076cce9f68a1a7bed5b76/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string15 = /4416b23c351acb1ea86eff2f75926ee7fbb78dea66fe2f01e38e9f81683645e9/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string16 = /57944ea45f77ef9b4757a95c077b30af638ed72c1399e75356f08cae37a3965f/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string17 = /5c4247c201d5bfb98cd4021c4cf0dd732c4fa47daeb4c70fcb29f7ddfe1b5760/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string18 = /616bcf6f1ebc84ce6c2f0469f6c38b08eabef2339dfca03d0782a54ae6cc6024/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string19 = /6794102a7b3d61dd4344b555ab684f4140d40da9ec0da36b03cd397f1987bb61/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string20 = /690f31d0d8f473ae1f71a7fbce1e7943d601f6adf2065d22d44162266c88f546/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string21 = /7f23ac69fa3f519b324bcc33e56272bf1cc9191980bef960a562099844659a3c/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string22 = /81317db18f63092007326ae6330d704c17d95ff2dfc65fc1922d0f3708ddee6e/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string23 = /873b15cab88f6d288e02bd71e5cefb1edf0b96dc80a8a0d7d404f4b327c68097/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string24 = /8eb3e6b0ac776c819158b0127631f860223f5fe80cc7297d01626252562cb866/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string25 = /8f904a5fd2b5c821121ad0003e3f4021cc5f1c2969d14e64e67ce35721ab6f70/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string26 = /9684712e7ea18e0e82bbdf8b990173349ac97423ab59b0daa265a222cfbef816/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string27 = /9dc3c784b09c7e143046fee8b0b96f2b2c92fa95aad96679e0ab79383e20647c/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string28 = /a11a44666cbdc5c56112cdb109e37c7f4f466f947500efce2192007d553a07f5/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string29 = /a5dd833c5c1f9ac79705b4fddd9d9e7dde9b25f5bbf79a7dc1c00537f181f47a/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string30 = /aacf0692bcac39321f5f427164f6807107ae9bc75404a07d009f553710d9bc55/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string31 = /b3f0715b807f2c31670a389cb430f01423f281d38f44e93d53e5fb2732406173/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string32 = /bb5f01316e315e4a9039a17dd2358cec0a86cac566638d8ce5e2ce0b5ebc1fbf/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string33 = /c6b4e0b176b29a3a2bf68e702195cbf72d705f8c6419ac17e7bfd16b18429447/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string34 = /cbdf3b97f6a72121a00e8f14fd0bbd564aefc6edfde0b9449f1613559678d09f/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string35 = /cc3badcfbd2bad09f5a4312eabdc50b2d2259cbac5429deb6e53340468c7b7b0/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string36 = /cde0f088445933eef88c2663bf2684f6e020d30347a7a230658d534c05f4e8d9/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string37 = /cf418ac948b21bbed8565d6f11419405aa7b25d3c37b8a2b212e85f6aa76d233/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string38 = /d5e79002815d4d904942d07786fab82492f83912d175804e21c059c00efe3d95/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string39 = /e7f434888e992b2679e221199354f80eaee1e7c3c546043f37aeefa3fbe252ae/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string40 = /edb84e2914bb1bd31a213b87aabd387999159093c5c00138cbc8f8f8fdc77fb1/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string41 = /f0ded25a361ea53de7518a357c03d733d8caf206f7a90a8e3b4d6a29563c9277/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string42 = /f955157646e94bed38b8e4d6ce6df58489eeb89ebf0d44ffe03b3c4902dc5d4e/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string43 = /mmatczuk\/go\-http\-tunnel\.git/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string44 = /tunnel\s\-config\s.{0,1000}tunnel\.yml/ nocase ascii wide
        // Description: Fast and secure tunnels over HTTP/2
        // Reference: https://github.com/mmatczuk/go-http-tunnel
        $string45 = /tunneld\s\-tlsCrt\s/ nocase ascii wide

    condition:
        any of them
}
