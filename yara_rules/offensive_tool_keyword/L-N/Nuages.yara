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
        $string1 = /\snuages\.formatImplantLastSeen/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string2 = /\sNuagesImplant/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string3 = /\!autoruns\s/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string4 = /\!files\supload\s/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string5 = /\!handlers\sload\s/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string6 = /\!implants\s/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string7 = /\!interactive\s/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string8 = /\!modules\sload\s/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string9 = /\!put\s.{0,1000}\/tmp/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string10 = /\!shell\s/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string11 = /\!tunnels\s\-\-tcp/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string12 = /\!use\s.{0,1000}aes256_py/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string13 = /\!use\s.{0,1000}reflected_assembly/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string14 = /\/implant\/callback/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string15 = /\/Nuages_Cli/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string16 = /\/nuagesAPI\.js/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string17 = /\\Nuages_Cli/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string18 = /before\-create\-implant\-callback/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string19 = /before\-create\-implant\-io\-bin/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string20 = /before\-find\-implant\-chunks/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string21 = /DNSAES256Handler\./ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string22 = /http.{0,1000}127\.0\.0\.1:3030/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string23 = /http.{0,1000}localhost:3030/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string24 = /HTTPAES256Handler\./ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string25 = /implant\-callback\./ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string26 = /Nuages.{0,1000}\/Implants/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string27 = /nuages\.clearImplants\s/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string28 = /nuages\.getAutoruns/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string29 = /nuages\.getImplants/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string30 = /nuages\.getListeners/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string31 = /nuages\.printImplants/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string32 = /nuages\.printListeners/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string33 = /nuages_cli\.js/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string34 = /NuagesC2Connector/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string35 = /NuagesC2Implant/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string36 = /NuagesPythonImplant/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string37 = /NuagesSharpImplant/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string38 = /p3nt4\/Nuages/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string39 = /posh_in_mem/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string40 = /processImplantMessage/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string41 = /runFakeTerminal/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string42 = /SLACKAES256Handler\./ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string43 = /Utils\\Posh\.cs/ nocase ascii wide

    condition:
        any of them
}
