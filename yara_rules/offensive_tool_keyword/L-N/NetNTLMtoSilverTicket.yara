rule NetNTLMtoSilverTicket
{
    meta:
        description = "Detection patterns for the tool 'NetNTLMtoSilverTicket' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetNTLMtoSilverTicket"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string1 = /.{0,1000}\sGet\-SpoolStatus\.ps1.{0,1000}/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string2 = /.{0,1000}\.\/hashcat\s\-.{0,1000}/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string3 = /.{0,1000}\/NetNTLMtoSilverTicket.{0,1000}/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string4 = /.{0,1000}\/ticketer\.py\s\-.{0,1000}/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string5 = /.{0,1000}\\Get\-SpoolStatus\.ps1.{0,1000}/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string6 = /.{0,1000}dementor\.py\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string7 = /.{0,1000}NetNTLMtoSilverTicket\.git.{0,1000}/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string8 = /.{0,1000}NetNTLMtoSilverTicket\-master.{0,1000}/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string9 = /.{0,1000}ntlmv1\.py\s\-\-ntlmv1\s.{0,1000}::.{0,1000}/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string10 = /.{0,1000}rpcdump\.py\s.{0,1000}\s\|\sgrep\sMS\-RPRN.{0,1000}/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string11 = /.{0,1000}SpoolSample\.exe\s.{0,1000}\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
