rule zrok
{
    meta:
        description = "Detection patterns for the tool 'zrok' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "zrok"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string1 = /\sadmin\screate\sfrontend\ssqJRAINSiB\spublic\s/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string2 = /\s\-c\srest_client_zrok\s\-t/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string3 = /\s\-s\srest_server_zrok\s\-t/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string4 = /\szrok\.listener/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string5 = /\$HOME\/\.zrok/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string6 = /\.in\.zrok\.io/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string7 = /\.share\.zrok\.io/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string8 = /\.zrok\.quigley\.com/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string9 = /\/\.zrok\/.{0,1000}\.json/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string10 = /\/\.zrok\:\/\.zrok/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string11 = /\/\/\sNewHTTPClient\screates\sa\snew\szrok\sHTTP\sclient\./ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string12 = /\/docker\/compose\/zrok\-instance\// nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string13 = /\/etc\/zrok\.env/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string14 = /\/etc\/zrok\// nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string15 = /\/rest_client_zrok\// nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string16 = /\/var\/lib\/zrok\-/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string17 = /\/zrok\.exe/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string18 = /\/zrok\.git/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string19 = /\/zrok\.zip/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string20 = /\/zrok\-amd64_darwin_amd64/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string21 = /\/zrok\-arm64_darwin_arm64/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string22 = /\/zrok\-controller\.log/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string23 = /\/zrok\-docker\// nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string24 = /\/zrok\-frontend\.log/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string25 = /\/zrok\-share\.env/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string26 = /\\zrok\.exe/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string27 = /\\zrok\.zip/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string28 = /\\zrok\-controller\.log/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string29 = /\\zrok\-frontend\.log/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string30 = /\>Welcome\snew\szrok\suser\!\</ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string31 = /\>Welcome\sto\szrok\!\</ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string32 = /\>zrok\sfrontend\shealth\:\sok\</ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string33 = /\>zrok\stest\sendpoint\</ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string34 = /25e850edd1cb8707c9a18a0fcc610b831cce25203dff650ec7e781175d900df3/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string35 = /4adeaf8287ac71363bb2c5ccd6b67b8c973f783702c18c444741875375772be1/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string36 = /651caf1b8d81a445db65551955dda4aa7df88a0013a81fda506bdfcfe05611b0/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string37 = /9af57a343f42da2250dd4499d6dcff61a7a6395eae77eaab0ddddbe544743116/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string38 = /d5be8ba1112a210428cac87772b6d7902a9b9299b9a658d03ffbc52e9d125593/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string39 = /def7512aaa595d7cad9b2e237a0ee99e778bbae0a30dd2eba75d099fc80f310f/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string40 = /http.{0,1000}api\.zrok\./ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string41 = /http\:\/\/.{0,1000}\.zrok\.io/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string42 = /http\:\/\/127\.0\.0\.1\:18080/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string43 = /http\:\/\/127\.0\.0\.1\:9191/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string44 = /https\:\/\/.{0,1000}\.zrok\.io/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string45 = /https\:\/\/zrok\./ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string46 = /openziti\/zrok/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string47 = /pastefrom\sb46p9j82z81f/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string48 = /share\.zrok\.io/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string49 = /tags\.zrokShareToken\=/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string50 = /the\szrok\senvironment\swas\ssuccessfully\senabled/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string51 = /zrockify_func\(/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string52 = /zrok\sadmin\sbootstrap/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string53 = /zrok\sconfiguration\supdated/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string54 = /zrok\senvironment\sdisabled/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string55 = /zrok\sshare\spublic\s/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string56 = /zrok\sshare\sreserved\s/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string57 = /zrok\stest\sloop\spublic/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string58 = /zrok\.environment\.root/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string59 = /zrok\.environment\.root\.Load/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string60 = /zrok\.proxy\.v1/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string61 = /zrok\.share\.CreateShare\(/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string62 = /zrok_api\.configuration/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string63 = /ZROK_BACKEND_MODE/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string64 = /ZROK_RESERVED_TOKEN/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string65 = /zrok\-share\.service/ nocase ascii wide
        // Description: zrok allows users to share tunnels for HTTP TCP and UDP network resources. zrok additionally allows users to easily and rapidly share files - web content and custom resources in a peer-to-peer manner.
        // Reference: https://github.com/openziti/zrok
        $string66 = /zrokSvcId\=/ nocase ascii wide

    condition:
        any of them
}
