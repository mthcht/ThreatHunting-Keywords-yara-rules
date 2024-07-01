rule level_io
{
    meta:
        description = "Detection patterns for the tool 'level.io' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "level.io"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string1 = /\s\.\/level\-darwin\-bundle\-amd64\.pkg/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string2 = /\s\.\/level\-linux\-amd64\s/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string3 = /\s\.\/level\-linux\-arm64\s/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string4 = /\s\/F\s\/TN\s\"Level\\Level\sWatchdog\"/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string5 = /\sdownloads\.level\.io/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string6 = /\"message\"\:\"ably\sconnection\sstate\:\sCONNECTED\"\}/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string7 = /\$env\:LEVEL_API_KEY\s\=\s\".{0,1000}\"\;/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string8 = /\$tempFile\s\=\sJoin\-Path\s\(\[System\.IO\.Path\]\:\:GetTempPath\(\)\)\s\"install_windows\.exe\"\;/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string9 = /\/etc\/level\/config\.yaml/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string10 = /\/level\-windows\-amd64\.exe/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string11 = /\/level\-windows\-arm64\.exe/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string12 = /\/usr\/local\/bin\/level/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string13 = /\/var\/lib\/level\/level\.db/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string14 = /\/var\/lib\/level\/level\.log/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string15 = /\\level\.exe.{0,1000}\-\-check\-service/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string16 = /\\level\-remote\-control\-ffmpeg\.exe\.download/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string17 = /\\level\-windows\-amd64\.exe/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string18 = /\\level\-windows\-arm64\.exe/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string19 = /\\Program\sFiles\s\(x86\)\\Level\\/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string20 = /\\Program\sFiles\\Level\\level\.db/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string21 = /\\Program\sFiles\\Level\\osqueryi\.exe/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string22 = /\\Program\sFiles\\Level\\winpty\.dll/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string23 = /\\Program\sFiles\\Level\\winpty\-agent\.exe/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string24 = /\\Temp\\install_windows\.exe/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string25 = /\<\\Level\\Level\sWatchdog\>/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string26 = /\>Level\sSoftware\,\sInc\.\</ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string27 = /\>Remote\sdevice\smanagement\s\-\shttps\:\/\/level\.io\</ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string28 = /37B9B43761672219E98BFA826E7AF17E799592BC57ACBC4AAC38DAF5EFAAF653/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string29 = /3DDF7FBB35EC90BCF15E723F1445EEB71E71C9757243EFEC1CEB4E74A10A1D9F/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string30 = /agents\.level\.io/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string31 = /builds\.level\.io/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string32 = /https\:\/\/app\.level\.io\/devices/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string33 = /https\:\/\/docs\.level\.io\/1\.0\/admin\-guides\/level\-watchdog\-task/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string34 = /https\:\/\/downloads\.level\.io\/install_linux\.sh/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string35 = /https\:\/\/downloads\.level\.io\/install_mac_os\.sh/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string36 = /https\:\/\/downloads\.level\.io\/install_windows\.exe/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string37 = /https\:\/\/downloads\.level\.io\/stable\/level\-linux\-amd64/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string38 = /LEVEL_API_KEY\=.{0,1000}\sbash\s\-c\s\"\$\(curl\s\-L\s/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string39 = /logs\.logdna\.com/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string40 = /netsh\s\sadvfirewall\sfirewall\sadd\srule\sname\=\\\"Level\sAgent\\\"/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string41 = /online\.level\.io/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string42 = /Program\sFiles\\Level\\level\.log/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string43 = /realtime\.ably\.io/ nocase ascii wide
        // Description: Level is reinventing remote monitoring and management
        // Reference: https://level.io/
        $string44 = /rest\.ably\.io/ nocase ascii wide

    condition:
        any of them
}
