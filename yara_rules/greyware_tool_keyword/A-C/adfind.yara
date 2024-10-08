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
        $string1 = /\sdclist\s/ nocase ascii wide
        // Description: Enumerate All Computers in the Domain
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string2 = /\s\-f\s\"\(objectcategory\=computer\)\"\s\-s\ssubtree\sdn\soperatingSystem/ nocase ascii wide
        // Description: Enumerate All Users in the Domain
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string3 = /\s\-f\s\"\(objectcategory\=person\)\"\s\-s\ssubtree\ssamaccountname\suserPrincipalName/ nocase ascii wide
        // Description: Dump All Domain Trusts
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string4 = /\s\-f\s\"\(objectcategory\=trustedDomain\)\"\s\-s\ssubtree\sname\strustAttributes\strustDirection\strustType/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string5 = /\s\-sc\strustdump/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/aancw/community-threats/blob/82ece2dec931d175ed47276d426f526610aa8262/Ryuk/VFS/adf.bat#L4
        $string6 = /\.exe\s\-gcb\s\-sc\strustdmp\s\>\s/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/aancw/community-threats/blob/82ece2dec931d175ed47276d426f526610aa8262/Ryuk/VFS/adf.bat#L4
        $string7 = /\.exe\s\-sc\sadinfo\s\>\s/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/aancw/community-threats/blob/82ece2dec931d175ed47276d426f526610aa8262/Ryuk/VFS/adf.bat#L4
        $string8 = /\.exe\s\-sc\sdclist\s\>\s/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/aancw/community-threats/blob/82ece2dec931d175ed47276d426f526610aa8262/Ryuk/VFS/adf.bat#L4
        $string9 = /\.exe\s\-sc\strustdmp\s\>\s/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/aancw/community-threats/blob/82ece2dec931d175ed47276d426f526610aa8262/Ryuk/VFS/adf.bat#L4
        $string10 = /\.exe\s\-subnets\s\-f\s\(objectCategory\=subnet\)\s\>\s/ nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string11 = /\/AdFind\.zip/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/aancw/community-threats/blob/82ece2dec931d175ed47276d426f526610aa8262/Ryuk/VFS/adf.bat#L4
        $string12 = /\\adf\.bat/ nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string13 = /\\adfind\.cf/ nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string14 = /\\AdFind\.zip/ nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string15 = /\>AdFind\</ nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string16 = /484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string17 = /adfind\s\-f\s/ nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string18 = /adfind\s\-f\sobjectclass\=trusteddomain/ nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string19 = /adfind\s\-sc\strustdmp/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string20 = /adfind\.bat/ nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string21 = /adfind\.exe\s\-f\sobjectclass\=trusteddomain/ nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string22 = /adfind\.exe\s\-sc\strustdmp/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string23 = /adfind\.exe/ nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string24 = /AdFind\\AdFind\.cpp/ nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string25 = /AdFind_original\.exe/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string26 = /computers_pwdnotreqd/ nocase ascii wide
        // Description: adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers are abusing it to gather valuable information about the network environment
        // Reference: https://www.virustotal.com/gui/file/484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384/behavior
        $string27 = /joeware_default_adfind\.cf/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string28 = /name\=.{0,1000}Domain\sAdmins/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string29 = /tools\/adfind/ nocase ascii wide

    condition:
        any of them
}
