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
        // Reference: N/A
        $string2 = /\s\-f\s\"\(objectcategory\=computer\)\"\s\-s\ssubtree\sdn\soperatingSystem/ nocase ascii wide
        // Description: Enumerate All Users in the Domain
        // Reference: N/A
        $string3 = /\s\-f\s\"\(objectcategory\=person\)\"\s\-s\ssubtree\ssamaccountname\suserPrincipalName/ nocase ascii wide
        // Description: Dump All Domain Trusts
        // Reference: N/A
        $string4 = /\s\-f\s\"\(objectcategory\=trustedDomain\)\"\s\-s\ssubtree\sname\strustAttributes\strustDirection\strustType/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string5 = /\s\-sc\strustdump/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string6 = /adfind\s\-f\s/ nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string7 = /adfind\s\-f\sobjectclass\=trusteddomain/ nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string8 = /adfind\s\-sc\strustdmp/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string9 = /adfind\.bat/ nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string10 = /adfind\.exe\s\-f\sobjectclass\=trusteddomain/ nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string11 = /adfind\.exe\s\-sc\strustdmp/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string12 = /adfind\.exe/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://www.joeware.net/freetools/tools/adfind/usage.htm
        $string13 = /AdFind\.zip/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string14 = /computers_pwdnotreqd/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string15 = /name\=.{0,1000}Domain\sAdmins/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string16 = /tools\/adfind/ nocase ascii wide

    condition:
        any of them
}
