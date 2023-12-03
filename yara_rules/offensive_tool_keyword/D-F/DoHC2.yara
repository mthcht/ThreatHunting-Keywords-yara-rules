rule DoHC2
{
    meta:
        description = "Detection patterns for the tool 'DoHC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DoHC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string1 = /.{0,1000}\/BeaconChannel\.cs.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string2 = /.{0,1000}\/DoHC2\.cs.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string3 = /.{0,1000}\/DoHC2\.git.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string4 = /.{0,1000}\/DoHC2\/.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string5 = /.{0,1000}\/ExternalC2\/.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string6 = /.{0,1000}\/WebC2\.cs.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string7 = /.{0,1000}\/WebSocketC2\.cs.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string8 = /.{0,1000}\\BeaconChannel\.cs.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string9 = /.{0,1000}\\BeaconConnector\.cs.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string10 = /.{0,1000}\\DoHC2\.cs.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string11 = /.{0,1000}\\ExternalC2\\.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string12 = /.{0,1000}0\.0\.0\.0:2222.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string13 = /.{0,1000}127\.0\.0\.1:2222.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string14 = /.{0,1000}C2WebSocketHandler\..{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string15 = /.{0,1000}Cobalt\sStrike\sexternal\sC2.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string16 = /.{0,1000}DoHC2.{0,1000}BeaconConnector.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string17 = /.{0,1000}DoHC2\.exe.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string18 = /.{0,1000}DoHC2\.py.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string19 = /.{0,1000}DoHC2Runner\..{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string20 = /.{0,1000}DoHC2Runner\.exe.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string21 = /.{0,1000}DoHC2Runner\.pdb.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string22 = /.{0,1000}DoHChannel\.cs.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string23 = /.{0,1000}external_c2\.cna.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string24 = /.{0,1000}ExternalC2\..{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string25 = /.{0,1000}ExternalC2\.dll.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string26 = /.{0,1000}externalc2_start.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string27 = /.{0,1000}ExternalC2Core.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string28 = /.{0,1000}ExternalC2\-master.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string29 = /.{0,1000}ExternalC2Tests.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string30 = /.{0,1000}ExternalC2Web.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string31 = /.{0,1000}go\-external\-c2.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string32 = /.{0,1000}package\sexternc2.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string33 = /.{0,1000}SpiderLabs\/DoHC2.{0,1000}/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string34 = /.{0,1000}X\-C2\-Beacon.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
