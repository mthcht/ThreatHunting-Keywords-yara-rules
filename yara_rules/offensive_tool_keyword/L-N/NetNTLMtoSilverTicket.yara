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
        $string1 = /\sdementor\.py/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string2 = /\sGet\-SpoolStatus\.ps1/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string3 = /\srpcdump\.py/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string4 = /\.\/hashcat\s\-/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string5 = /\/dementor\.py/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string6 = /\/NetNTLMtoSilverTicket/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string7 = /\/rpcdump\.py/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string8 = /\/ticketer\.py\s\-/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string9 = /\\dementor\.py/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string10 = /\\Get\-SpoolStatus\.ps1/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string11 = /\\rpcdump\.py/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string12 = /a8421a872b4c4eccc02a0ebb623f9ecc2991e949e4134fc184ca1822da0e5c4c/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string13 = /dementor\s\-\srough\sPoC\sto\sconnect\sto\sspoolss\sto\selicit\smachine\saccount\sauthentication\s/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string14 = /dementor\.py\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string15 = /Got\sexpected\sRPC_S_SERVER_UNAVAILABLE\sexception\.\sAttack\sworked/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string16 = /impacket\.dcerpc\.v5/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string17 = /NetNTLMtoSilverTicket\.git/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string18 = /NetNTLMtoSilverTicket\-master/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string19 = /ntlmv1\.py\s\-\-ntlmv1\s.{0,1000}\:\:/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string20 = /python3\sntlmv1\.py\s/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string21 = /Responder\.py\s\-I\s/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string22 = /rpcdump\.py\s.{0,1000}\s\|\sgrep\sMS\-RPRN/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string23 = /SpoolSample\.exe\s.{0,1000}\s/ nocase ascii wide
        // Description: Obtaining NetNTLMv1 Challenge/Response authentication - cracking those to NTLM Hashes and using that NTLM Hash to sign a Kerberos Silver ticket.
        // Reference: https://github.com/NotMedic/NetNTLMtoSilverTicket
        $string24 = /ticketer\.py\s\-nthash\s/ nocase ascii wide

    condition:
        any of them
}
