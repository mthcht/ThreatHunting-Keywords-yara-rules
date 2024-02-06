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
        $string1 = /\sGet\-SpoolStatus\.ps1/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string2 = /\.\/hashcat\s\-/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string3 = /\/NetNTLMtoSilverTicket/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string4 = /\/ticketer\.py\s\-/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string5 = /\\Get\-SpoolStatus\.ps1/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string6 = /dementor\.py\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string7 = /NetNTLMtoSilverTicket\.git/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string8 = /NetNTLMtoSilverTicket\-master/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string9 = /ntlmv1\.py\s\-\-ntlmv1\s.{0,1000}\:\:/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string10 = /rpcdump\.py\s.{0,1000}\s\|\sgrep\sMS\-RPRN/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string11 = /SpoolSample\.exe\s.{0,1000}\s/ nocase ascii wide

    condition:
        any of them
}
