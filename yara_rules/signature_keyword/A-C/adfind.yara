rule adfind
{
    meta:
        description = "Detection patterns for the tool 'adfind' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adfind"
        rule_category = "signature_keyword"

    strings:
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string1 = /AdFind\s\(PUA\)/ nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string2 = "HackTool:Win32/AdFind" nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string3 = /RiskWare\.AdFind/ nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string4 = "Riskware/AdFind" nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string5 = /Trojan\:Win32\/RemoteSysDisc\.E\!adfind/ nocase ascii wide

    condition:
        any of them
}
