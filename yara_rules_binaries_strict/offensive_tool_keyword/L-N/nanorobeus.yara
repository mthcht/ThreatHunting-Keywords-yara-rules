rule nanorobeus
{
    meta:
        description = "Detection patterns for the tool 'nanorobeus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nanorobeus"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string1 = /\skekeo\/modules\/kull_m_memory\.c/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string2 = " kerberoast /spn:" nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string3 = " tgtdeleg /spn:cifs" nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string4 = /\/kerberoast\.c/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string5 = /\/modules\/kull_m_crypto_system\.h/
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string6 = /\/nanorobeus\.git/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string7 = /\\include\\kerberoast\.h/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string8 = /\\kerberoast\.c/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string9 = /\\kerberoast\.c/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string10 = /\\nanorobeus\-main\.zip/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string11 = /\\sample_brc4\.json/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string12 = /\\sample_sliver\.json/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string13 = /dist.{0,100}_brc4\.x64\.o/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string14 = /dist.{0,100}_brc4\.x86\.o/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string15 = /dist\/nanorobeus_cs\./ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string16 = /nanorobeus.{0,100}_cs\.x64\./ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string17 = /nanorobeus.{0,100}_cs\.x86\./ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string18 = /nanorobeus.{0,100}dump/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string19 = /nanorobeus\.cna/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string20 = /nanorobeus\.x64/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string21 = /nanorobeus\.x86/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string22 = "nanorobeus_brc4" nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string23 = "nanorobeus64" nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string24 = "nanorobeus86" nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string25 = "nanorobeus-main" nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string26 = /sample_brc4\.json/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string27 = "wavvs/nanorobeus" nocase ascii wide
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
