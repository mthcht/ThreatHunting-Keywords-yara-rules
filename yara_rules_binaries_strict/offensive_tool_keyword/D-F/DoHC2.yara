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
        $string1 = /\/BeaconChannel\.cs/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string2 = /\/DoHC2\.cs/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string3 = /\/DoHC2\.git/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string4 = "/DoHC2/" nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string5 = "/ExternalC2/" nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string6 = /\/WebC2\.cs/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string7 = /\/WebSocketC2\.cs/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string8 = /\\BeaconChannel\.cs/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string9 = /\\BeaconConnector\.cs/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string10 = /\\DoHC2\.cs/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string11 = /\\ExternalC2\\/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string12 = /0\.0\.0\.0\:2222/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string13 = /127\.0\.0\.1\:2222/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string14 = /C2WebSocketHandler\./ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string15 = "Cobalt Strike external C2" nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string16 = /DoHC2.{0,100}BeaconConnector/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string17 = /DoHC2\.exe/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string18 = /DoHC2\.py/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string19 = /DoHC2Runner\./ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string20 = /DoHC2Runner\.exe/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string21 = /DoHC2Runner\.pdb/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string22 = /DoHChannel\.cs/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string23 = /external_c2\.cna/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string24 = /ExternalC2\./ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string25 = /ExternalC2\.dll/ nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string26 = "externalc2_start" nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string27 = "ExternalC2Core" nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string28 = "ExternalC2-master" nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string29 = "ExternalC2Tests" nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string30 = "ExternalC2Web" nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string31 = "go-external-c2" nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string32 = "package externc2" nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string33 = "SpiderLabs/DoHC2" nocase ascii wide
        // Description: DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
        // Reference: https://github.com/SpiderLabs/DoHC2
        $string34 = "X-C2-Beacon" nocase ascii wide
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
