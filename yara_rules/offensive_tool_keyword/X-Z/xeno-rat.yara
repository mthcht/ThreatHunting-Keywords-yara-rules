rule xeno_rat
{
    meta:
        description = "Detection patterns for the tool 'xeno-rat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xeno-rat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string1 = /\/xeno\-rat\.git/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string2 = /\\CurrentVersion\\Run\\XenoUpdateManager/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string3 = /\\InfoGrab\.dll/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string4 = /\\keyLogger\.cs/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string5 = /\\KeyLoggerOffline\./ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string6 = /\\LiveMicrophone\.dll/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string7 = /\\OfflineKeyloggerPipe/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string8 = /\\Programs\\StartUp\\XenoUpdateManager/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string9 = /\\ReverseProxy\.dll/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string10 = /\\xeno\srat\sserver\./ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string11 = /\\xeno\srat\sserver\\/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string12 = /\\xeno\-rat\\/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string13 = /\\xeno\-rat\-main/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string14 = /06B2B14A\-CE87\-41C0\-A77A\-2644FE3231C7/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string15 = /13A59BB8\-0246\-4FFA\-951B\-89B9A341F159/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string16 = /310FC5BE\-6F5E\-479C\-A246\-6093A39296C0/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string17 = /4F169EA5\-8854\-4258\-9D2C\-D44F37D88776/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string18 = /534D9A24\-3138\-4209\-A4C6\-6B9C1EF0B579/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string19 = /644AFE4A\-2267\-4DF9\-A79D\-B514FB31830E/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string20 = /70795D10\-8ADF\-4A4D\-A584\-9AB1BBF40D4B/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string21 = /8493D0F0\-CA01\-4C5A\-A6E3\-C0F427966ABD/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string22 = /8A15D28C\-252A\-4FCC\-8BBD\-BC3802C0320A/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string23 = /8B605B2E\-AAD2\-46FB\-A348\-27E3AABA4C9C/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string24 = /9CCE5C71\-14B4\-4A08\-958D\-4E593975658B/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string25 = /A138FC2A\-7BFF\-4B3C\-94A0\-62A8BC01E8C0/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string26 = /A64EF001\-BE90\-4CF5\-86B2\-22DFDB49AE81/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string27 = /A9EAA820\-EC72\-4052\-80D0\-A2CCBFCC83E6/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string28 = /C346B912\-51F2\-4A2E\-ACC3\-0AC2D28920C6/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string29 = /C373A937\-312C\-4C8D\-BD04\-BAAF568337E7/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string30 = /D3E7005E\-6C5B\-47F3\-A0B3\-028C81C0C1ED/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string31 = /F60C3246\-D449\-412B\-A858\-3B5E84494D1A/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string32 = /F61EEB46\-5352\-4349\-B880\-E4A0B38EC0DB/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string33 = /https\:\/\/t\.me\/moom825/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string34 = /KeyLogger\.dll/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string35 = /KeyLoggerOffline\.dll/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string36 = /L0MgY2hvaWNlIC9DIFkgL04gL0QgWSAvVCAzICYgRGVsICI\=/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string37 = /moom825\/xeno\-rat/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string38 = /plugins\\ScreenControl\.dll/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string39 = /Ransom\:Win32\/Sodinokibi/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string40 = /Uacbypass\.dll/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string41 = /\-\-user\-data\-dir\=C\:\\\\chrome\-dev\-profile23\s\-\-remote\-debugging\-port\=9222/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string42 = /xeno\srat\sclient\.exe/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string43 = /xeno\srat\sserver\.exe/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string44 = /xeno\%20rat\%20client\.exe/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string45 = /xeno\%20rat\%20server\.exe/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string46 = /Xeno_manager\.exe/ nocase ascii wide
        // Description: Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // Reference: https://github.com/moom825/xeno-rat
        $string47 = /XenoUpdateManager\.lnk/ nocase ascii wide

    condition:
        any of them
}
