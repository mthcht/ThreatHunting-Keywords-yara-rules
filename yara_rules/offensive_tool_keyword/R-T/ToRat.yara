rule ToRat
{
    meta:
        description = "Detection patterns for the tool 'ToRat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ToRat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string1 = /\/dist\:\/dist_ext\storat/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string2 = /\/persist_cortana\.py/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string3 = /\/persist_people\.py/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string4 = /\/persit_linux\.go/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string5 = /\/persit_windows\.go/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string6 = /\/ToRat\.git/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string7 = /\/tor\-static\-windows\-amd64\.zip/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string8 = /\\persist_cortana\.py/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string9 = /\\persist_people\.py/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string10 = /\\persit_linux\.go/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string11 = /\\persit_windows\.go/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string12 = /\\ToRat\\cmd\\/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string13 = /\\ToRat\\keygen\\/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string14 = /\\ToRat\\torat_client\\/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string15 = /\\ToRat\\torat_server\\/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string16 = /\\ToRat\-master\.zip/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string17 = /\\tor\-static\-windows\-amd64\.zip/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string18 = /docker\sbuild\s\.\s\-t\storat/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string19 = /docker\srun\s\-it\storat/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string20 = /localhost\:8000\/.{0,1000}\/hardware/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string21 = /localhost\:8000\/.{0,1000}\/netscan/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string22 = /localhost\:8000\/.{0,1000}\/osinfo/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string23 = /localhost\:8000\/.{0,1000}\/speedtest/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string24 = /lu4p\/ToRat/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string25 = /server\/ToRat_server/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string26 = /torEd25519/ nocase ascii wide

    condition:
        any of them
}
