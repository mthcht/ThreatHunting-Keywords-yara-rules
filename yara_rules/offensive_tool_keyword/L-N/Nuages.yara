rule Nuages
{
    meta:
        description = "Detection patterns for the tool 'Nuages' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nuages"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string1 = /.{0,1000}\snuages\.formatImplantLastSeen.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string2 = /.{0,1000}\sNuagesImplant.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string3 = /.{0,1000}\!autoruns\s.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string4 = /.{0,1000}\!files\supload\s.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string5 = /.{0,1000}\!handlers\sload\s.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string6 = /.{0,1000}\!implants\s.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string7 = /.{0,1000}\!interactive\s.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string8 = /.{0,1000}\!modules\sload\s.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string9 = /.{0,1000}\!put\s.{0,1000}\/tmp.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string10 = /.{0,1000}\!shell\s.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string11 = /.{0,1000}\!tunnels\s\-\-tcp.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string12 = /.{0,1000}\!use\s.{0,1000}aes256_py.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string13 = /.{0,1000}\!use\s.{0,1000}reflected_assembly.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string14 = /.{0,1000}\/implant\/callback.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string15 = /.{0,1000}\/Nuages_Cli.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string16 = /.{0,1000}\/nuagesAPI\.js.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string17 = /.{0,1000}\\Nuages_Cli.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string18 = /.{0,1000}before\-create\-implant\-callback.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string19 = /.{0,1000}before\-create\-implant\-io\-bin.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string20 = /.{0,1000}before\-find\-implant\-chunks.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string21 = /.{0,1000}DNSAES256Handler\..{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string22 = /.{0,1000}http.{0,1000}127\.0\.0\.1:3030.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string23 = /.{0,1000}http.{0,1000}localhost:3030.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string24 = /.{0,1000}HTTPAES256Handler\..{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string25 = /.{0,1000}implant\-callback\..{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string26 = /.{0,1000}Nuages.{0,1000}\/Implants.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string27 = /.{0,1000}nuages\.clearImplants\s.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string28 = /.{0,1000}nuages\.getAutoruns.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string29 = /.{0,1000}nuages\.getImplants.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string30 = /.{0,1000}nuages\.getListeners.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string31 = /.{0,1000}nuages\.printImplants.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string32 = /.{0,1000}nuages\.printListeners.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string33 = /.{0,1000}nuages_cli\.js.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string34 = /.{0,1000}NuagesC2Connector.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string35 = /.{0,1000}NuagesC2Implant.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string36 = /.{0,1000}NuagesPythonImplant.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string37 = /.{0,1000}NuagesSharpImplant.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string38 = /.{0,1000}p3nt4\/Nuages.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string39 = /.{0,1000}posh_in_mem.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string40 = /.{0,1000}processImplantMessage.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string41 = /.{0,1000}runFakeTerminal.{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string42 = /.{0,1000}SLACKAES256Handler\..{0,1000}/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string43 = /.{0,1000}Utils\\Posh\.cs.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
