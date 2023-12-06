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
        $string1 = /\skerberoast\s\/spn:/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string2 = /\stgtdeleg\s\/spn:cifs/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string3 = /\/kerberoast\.c/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string4 = /\/nanorobeus\.git/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string5 = /\?sample_sliver\.json/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string6 = /\\kerberoast\.c/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string7 = /dist.{0,1000}_brc4\.x64\.o/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string8 = /dist.{0,1000}_brc4\.x86\.o/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string9 = /dist\/nanorobeus_cs\./ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string10 = /nanorobeus.{0,1000}_cs\.x64\./ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string11 = /nanorobeus.{0,1000}_cs\.x86\./ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string12 = /nanorobeus.{0,1000}dump/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string13 = /nanorobeus\.cna/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string14 = /nanorobeus\.x64/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string15 = /nanorobeus\.x86/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string16 = /nanorobeus_brc4/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string17 = /nanorobeus64/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string18 = /nanorobeus86/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string19 = /nanorobeus\-main/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string20 = /sample_brc4\.json/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string21 = /wavvs\/nanorobeus/ nocase ascii wide

    condition:
        any of them
}
