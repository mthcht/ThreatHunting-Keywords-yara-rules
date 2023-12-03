rule adfind
{
    meta:
        description = "Detection patterns for the tool 'adfind' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adfind"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in lateral movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string1 = /.{0,1000}\sdclist\s.{0,1000}/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in lateral movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string2 = /.{0,1000}\s\-sc\strustdump.{0,1000}/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in lateral movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string3 = /.{0,1000}adfind\s\-f\s.{0,1000}/ nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string4 = /.{0,1000}adfind\s\-f\sobjectclass\=trusteddomain.{0,1000}/ nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string5 = /.{0,1000}adfind\s\-sc\strustdmp.{0,1000}/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in lateral movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string6 = /.{0,1000}adfind\.bat.{0,1000}/ nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string7 = /.{0,1000}adfind\.exe\s\-f\sobjectclass\=trusteddomain.{0,1000}/ nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string8 = /.{0,1000}adfind\.exe\s\-sc\strustdmp.{0,1000}/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in lateral movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string9 = /.{0,1000}adfind\.exe.{0,1000}/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in lateral movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://www.joeware.net/freetools/tools/adfind/usage.htm
        $string10 = /.{0,1000}AdFind\.zip.{0,1000}/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in lateral movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string11 = /.{0,1000}computers_pwdnotreqd.{0,1000}/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in lateral movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string12 = /.{0,1000}name\=.{0,1000}Domain\sAdmins.{0,1000}/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in lateral movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string13 = /.{0,1000}tools\/adfind.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
