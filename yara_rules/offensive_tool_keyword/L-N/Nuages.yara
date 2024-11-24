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
        $string2 = " NuagesImplant" nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string3 = "!autoruns " nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string4 = "!files upload " nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string5 = "!handlers load " nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string6 = "!implants " nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string7 = "!modules load " nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string8 = /\!put\s.{0,1000}\/tmp/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string9 = "!tunnels --tcp" nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string10 = /\!use\s.{0,1000}aes256_py/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string11 = /\!use\s.{0,1000}reflected_assembly/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string12 = "/implant/callback" nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string13 = "/Nuages_Cli" nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string14 = /\/nuagesAPI\.js/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string15 = /\\Nuages_Cli/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string16 = "before-create-implant-callback" nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string17 = "before-create-implant-io-bin" nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string18 = "before-find-implant-chunks" nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string19 = /DNSAES256Handler\./ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string20 = /http.{0,1000}127\.0\.0\.1\:3030/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string21 = /http.{0,1000}localhost\:3030/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string22 = /HTTPAES256Handler\./ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string23 = /implant\-callback\./ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string24 = /Nuages.{0,1000}\/Implants/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string25 = /nuages\.clearImplants\s/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string26 = /nuages\.getAutoruns/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string27 = /nuages\.getImplants/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string28 = /nuages\.getListeners/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string29 = /nuages\.printImplants/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string30 = /nuages\.printListeners/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string31 = /nuages_cli\.js/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string32 = "NuagesC2Connector" nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string33 = "NuagesC2Implant" nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string34 = "NuagesPythonImplant" nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string35 = "NuagesSharpImplant" nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string36 = "p3nt4/Nuages" nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string37 = "posh_in_mem" nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string38 = "processImplantMessage" nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string39 = "runFakeTerminal" nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string40 = /SLACKAES256Handler\./ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string41 = /Utils\\Posh\.cs/ nocase ascii wide

    condition:
        any of them
}
