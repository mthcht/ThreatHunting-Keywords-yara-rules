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
        $string1 = /.{0,1000}\skerberoast\s\/spn:.{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string2 = /.{0,1000}\stgtdeleg\s\/spn:cifs.{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string3 = /.{0,1000}\/kerberoast\.c.{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string4 = /.{0,1000}\/nanorobeus\.git.{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string5 = /.{0,1000}\?sample_sliver\.json.{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string6 = /.{0,1000}\\kerberoast\.c.{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string7 = /.{0,1000}dist.{0,1000}_brc4\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string8 = /.{0,1000}dist.{0,1000}_brc4\.x86\.o.{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string9 = /.{0,1000}dist\/nanorobeus_cs\..{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string10 = /.{0,1000}nanorobeus.{0,1000}_cs\.x64\..{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string11 = /.{0,1000}nanorobeus.{0,1000}_cs\.x86\..{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string12 = /.{0,1000}nanorobeus.{0,1000}dump.{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string13 = /.{0,1000}nanorobeus\.cna.{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string14 = /.{0,1000}nanorobeus\.x64.{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string15 = /.{0,1000}nanorobeus\.x86.{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string16 = /.{0,1000}nanorobeus_brc4.{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string17 = /.{0,1000}nanorobeus64.{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string18 = /.{0,1000}nanorobeus86.{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string19 = /.{0,1000}nanorobeus\-main.{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string20 = /.{0,1000}sample_brc4\.json.{0,1000}/ nocase ascii wide
        // Description: COFF file (BOF) for managing Kerberos tickets.
        // Reference: https://github.com/wavvs/nanorobeus
        $string21 = /.{0,1000}wavvs\/nanorobeus.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
