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
        $string7 = /\!modules\sload\s/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string8 = /\!put\s.{0,100}\/tmp/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string9 = /\!tunnels\s\-\-tcp/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string10 = /\!use\s.{0,100}aes256_py/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string11 = /\!use\s.{0,100}reflected_assembly/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string12 = /\/implant\/callback/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string13 = /\/Nuages_Cli/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string14 = /\/nuagesAPI\.js/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string15 = /\\Nuages_Cli/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string16 = /before\-create\-implant\-callback/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string17 = /before\-create\-implant\-io\-bin/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string18 = /before\-find\-implant\-chunks/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string19 = /DNSAES256Handler\./ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string20 = /http.{0,100}127\.0\.0\.1\:3030/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string21 = /http.{0,100}localhost\:3030/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string22 = /HTTPAES256Handler\./ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string23 = /implant\-callback\./ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string24 = /Nuages.{0,100}\/Implants/ nocase ascii wide
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
        $string32 = /NuagesC2Connector/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string33 = /NuagesC2Implant/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string34 = /NuagesPythonImplant/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string35 = /NuagesSharpImplant/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string36 = /p3nt4\/Nuages/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string37 = /posh_in_mem/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string38 = /processImplantMessage/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string39 = /runFakeTerminal/ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string40 = /SLACKAES256Handler\./ nocase ascii wide
        // Description: A modular C2 framework
        // Reference: https://github.com/p3nt4/Nuages
        $string41 = /Utils\\Posh\.cs/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
