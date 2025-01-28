rule adfind
{
    meta:
        description = "Detection patterns for the tool 'adfind' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adfind"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string1 = " dclist " nocase ascii wide
        // Description: Enumerate All Computers in the Domain
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string2 = /\s\-f\s\\"\(objectcategory\=computer\)\\"\s\-s\ssubtree\sdn\soperatingSystem/ nocase ascii wide
        // Description: Enumerate All Users in the Domain
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string3 = /\s\-f\s\\"\(objectcategory\=person\)\\"\s\-s\ssubtree\ssamaccountname\suserPrincipalName/ nocase ascii wide
        // Description: Dump All Domain Trusts
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string4 = /\s\-f\s\\"\(objectcategory\=trustedDomain\)\\"\s\-s\ssubtree\sname\strustAttributes\strustDirection\strustType/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: N/A
        $string5 = " -sc getacls -sddlfilter " nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string6 = " -sc trustdump" nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/aancw/community-threats/blob/82ece2dec931d175ed47276d426f526610aa8262/Ryuk/VFS/adf.bat#L4
        $string7 = /\.exe\s\-gcb\s\-sc\strustdmp\s\>\s/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/aancw/community-threats/blob/82ece2dec931d175ed47276d426f526610aa8262/Ryuk/VFS/adf.bat#L4
        $string8 = /\.exe\s\-sc\sadinfo\s\>\s/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/aancw/community-threats/blob/82ece2dec931d175ed47276d426f526610aa8262/Ryuk/VFS/adf.bat#L4
        $string9 = /\.exe\s\-sc\sdclist\s\>\s/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string10 = /\.exe\s\-sc\sgetacls\s\-sddlfilter\s/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/aancw/community-threats/blob/82ece2dec931d175ed47276d426f526610aa8262/Ryuk/VFS/adf.bat#L4
        $string11 = /\.exe\s\-sc\strustdmp\s\>\s/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/aancw/community-threats/blob/82ece2dec931d175ed47276d426f526610aa8262/Ryuk/VFS/adf.bat#L4
        $string12 = /\.exe\s\-subnets\s\-f\s\(objectCategory\=subnet\)\s\>\s/ nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string13 = /\/AdFind\.zip/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/aancw/community-threats/blob/82ece2dec931d175ed47276d426f526610aa8262/Ryuk/VFS/adf.bat#L4
        $string14 = /\\adf\.bat/ nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string15 = /\\adfind\.cf/ nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string16 = /\\AdFind\.zip/ nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string17 = ">AdFind<" nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string18 = "20b1918318148e410159d729ffcc373932073e2a68e993cc4440fc7df214471d" nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string19 = "484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384" nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string20 = "776a81b705827758d8810b9985a23ac59dc4cfd7ac616f0f08373d188d8291e6" nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string21 = "8f4662a487860ced024b2b38e6386a97ff7986313778a54a559eb0fc52e98606" nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string22 = "93c99378e20e88a9b81826b6619fde2bf261b278cfc2cdb79697a1575f9120fc" nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string23 = "adfind -f " nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string24 = "adfind -f objectclass=trusteddomain" nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string25 = "adfind -sc trustdmp" nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string26 = /adfind\.bat/ nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string27 = /adfind\.exe\s\-f\sobjectclass\=trusteddomain/ nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string28 = /adfind\.exe\s\-sc\strustdmp/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string29 = /adfind\.exe/ nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string30 = /AdFind\\AdFind\.cpp/ nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string31 = /AdFind_original\.exe/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string32 = "ce7c494c2959f874740bab1c74b444d776c9d6550337c8c046a1ddd795194b98" nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string33 = "computers_pwdnotreqd" nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string34 = /joeware_default_adfind\.cf/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string35 = "tools/adfind" nocase ascii wide

    condition:
        any of them
}
