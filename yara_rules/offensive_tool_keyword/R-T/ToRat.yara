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
        $string1 = /.{0,1000}\/dist:\/dist_ext\storat.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string2 = /.{0,1000}\/persist_cortana\.py.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string3 = /.{0,1000}\/persist_people\.py.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string4 = /.{0,1000}\/persit_linux\.go.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string5 = /.{0,1000}\/persit_windows\.go.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string6 = /.{0,1000}\/ToRat\.git.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string7 = /.{0,1000}\/tor\-static\-windows\-amd64\.zip.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string8 = /.{0,1000}\\persist_cortana\.py.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string9 = /.{0,1000}\\persist_people\.py.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string10 = /.{0,1000}\\persit_linux\.go.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string11 = /.{0,1000}\\persit_windows\.go.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string12 = /.{0,1000}\\ToRat\\cmd\\.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string13 = /.{0,1000}\\ToRat\\keygen\\.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string14 = /.{0,1000}\\ToRat\\torat_client\\.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string15 = /.{0,1000}\\ToRat\\torat_server\\.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string16 = /.{0,1000}\\ToRat\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string17 = /.{0,1000}\\tor\-static\-windows\-amd64\.zip.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string18 = /.{0,1000}docker\sbuild\s\.\s\-t\storat.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string19 = /.{0,1000}docker\srun\s\-it\storat.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string20 = /.{0,1000}localhost:8000\/.{0,1000}\/hardware.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string21 = /.{0,1000}localhost:8000\/.{0,1000}\/netscan.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string22 = /.{0,1000}localhost:8000\/.{0,1000}\/osinfo.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string23 = /.{0,1000}localhost:8000\/.{0,1000}\/speedtest.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string24 = /.{0,1000}lu4p\/ToRat.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string25 = /.{0,1000}server\/ToRat_server.{0,1000}/ nocase ascii wide
        // Description: ToRat is a Remote Administation tool written in Go using Tor as a transport mechanism and RPC for communication
        // Reference: https://github.com/lu4p/ToRat
        $string26 = /.{0,1000}torEd25519.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
