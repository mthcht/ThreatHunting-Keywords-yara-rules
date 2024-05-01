rule boringproxy
{
    meta:
        description = "Detection patterns for the tool 'boringproxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "boringproxy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string1 = /\sboringproxy\-client\.service/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string2 = /\sboringproxy\-server\.service/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string3 = /\s\-m\sboringproxy/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string4 = /\.\/boringproxy\sserver/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string5 = /\/bin\/boringproxy/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string6 = /\/boringproxy\.git/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string7 = /\/boringproxy\-client\.service/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string8 = /\/boringproxy\-server\.service/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string9 = /\/home\/boringproxy/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string10 = /\/tmp\/boringproxy\-client/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string11 = /23d61c88520628dc2ab58b25e556df92640327ca4f946cd8ea30eb813897d107/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string12 = /34362de1defeb018d71e6319afabca362fa4acd69341bfcfb3ce77b6e8c61a6a/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string13 = /403d4848966e4e5e7859758766269a5340f309c641e71f65fd3cf4b01049b8d9/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string14 = /47532247f32b7a9f42b0dfe5a1314a674e92deef79eaab647af34507a677d375/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string15 = /5805e0f064ce3aa72e5a0b4dd00c0bf4150995cb1f1b7b80f2b3a78da78d1d27/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string16 = /7a778797dd640eb51defe912e8b6872df92241927193106590a2ccb92a5dc926/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string17 = /828ee46c07c36e54f11e38f01898e3bd215739c28bbcf05606abe00ba0c6c51f/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string18 = /89bd3a31299f6bbf9be9bcf5f1456c11333590290626f11017079fd84ee58ca1/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string19 = /9a688243e33a6cddb1bb4807277e352118141e7321385024cbff655a00b7b660/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string20 = /a262487a6bac019c52f1ada940aa357f0be3c69cf1232a052115e74723a65ade/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string21 = /b4f3bc92ccedfbb0714c662c8d6a7842e71f1ebb2d8392ec5064b314dd5dede5/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string22 = /boringproxy\sclient\s\-server\s/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string23 = /boringproxy\/boringproxy/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string24 = /boringproxy_db\.json/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string25 = /boringproxy\-client\@default\.service/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string26 = /chown\sboringproxy\:boringproxy\s/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string27 = /cmd\/boringproxy/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string28 = /f2915f5a3885391738923ecd18faf840074c65cd2e390e1474a4d84ce315b9ff/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string29 = /f5b42d933cea4d53aa975039de0cb1053287fac5ce4377d2afb663e26a5d22dd/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string30 = /groupadd\sboringproxy/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string31 = /https\:\/\/boringproxy\.io\/installation/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string32 = /pkill\s\-u\sboringproxy/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string33 = /runuser\s\-l\sboringproxy\s/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string34 = /setcap\scap_net_bind_service\=\+ep\sboringproxy/ nocase ascii wide
        // Description: Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters.
        // Reference: https://github.com/boringproxy/boringproxy
        $string35 = /usermod\s\-a\s\-G\sboringproxy\sboringproxy/ nocase ascii wide

    condition:
        any of them
}
