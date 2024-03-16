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
        $string2 = /\skerberoast\s\/spn\:/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string3 = /\stgtdeleg\s\/spn\:cifs/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string4 = /\/kerberoast\.c/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string5 = /\/modules\/kull_m_crypto_system\.h/ nocase ascii wide
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
        $string13 = /dist.{0,1000}_brc4\.x64\.o/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string14 = /dist.{0,1000}_brc4\.x86\.o/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string15 = /dist\/nanorobeus_cs\./ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string16 = /nanorobeus.{0,1000}_cs\.x64\./ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string17 = /nanorobeus.{0,1000}_cs\.x86\./ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string18 = /nanorobeus.{0,1000}dump/ nocase ascii wide
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
        $string22 = /nanorobeus_brc4/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string23 = /nanorobeus64/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string24 = /nanorobeus86/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string25 = /nanorobeus\-main/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string26 = /sample_brc4\.json/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string27 = /wavvs\/nanorobeus/ nocase ascii wide

    condition:
        any of them
}
