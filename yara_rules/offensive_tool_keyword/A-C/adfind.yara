rule adfind
{
    meta:
        description = "Detection patterns for the tool 'adfind' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adfind"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Other/AdFind
        $string1 = /adfind\s\-gcb\s\-sc\strustdmp/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Other/AdFind
        $string2 = /adfind\s\-sc\sadinfo/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Other/AdFind
        $string3 = /adfind\s\-sc\scomputers_pwdnotreqd/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Other/AdFind
        $string4 = /adfind\s\-sc\sdclist/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Other/AdFind
        $string5 = /adfind\s\-sc\sdcmodes/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Other/AdFind
        $string6 = /adfind\s\-sc\sdomainlist/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Other/AdFind
        $string7 = /adfind\s\-sc\strustdmp/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in Lateral Movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Other/AdFind
        $string8 = /adfind\s\-subnets/ nocase ascii wide
        // Description: attackers perform Active Directory collection using AdFind in batch scripts from C:\Windows\Temp\adf\ or C:\temp\ and store output in CSV files
        // Reference: http://www.joeware.net/freetools/tools/adfind/index.htm
        $string9 = /adfind\.exe\s\-f\s\(objectcategory\=organizationalUnit\)\s\>\s.{0,1000}\.txt/ nocase ascii wide
        // Description: attackers perform Active Directory collection using AdFind in batch scripts from C:\Windows\Temp\adf\ or C:\temp\ and store output in CSV files
        // Reference: http://www.joeware.net/freetools/tools/adfind/index.htm
        $string10 = /adfind\.exe\s\-f\s\(objectcategory\=person\)\s\>\s.{0,1000}\.txt/ nocase ascii wide
        // Description: attackers perform Active Directory collection using AdFind in batch scripts from C:\Windows\Temp\adf\ or C:\temp\ and store output in CSV files
        // Reference: http://www.joeware.net/freetools/tools/adfind/index.htm
        $string11 = /adfind\.exe\s\-f\s.{0,1000}\(objectcategory\=group\).{0,1000}\s\>\s.{0,1000}\.txt/ nocase ascii wide
        // Description: attackers perform Active Directory collection using AdFind in batch scripts from C:\Windows\Temp\adf\ or C:\temp\ and store output in CSV files
        // Reference: http://www.joeware.net/freetools/tools/adfind/index.htm
        $string12 = /adfind\.exe\s\-f\sobjectcategory\=computer\s\>\s.{0,1000}\.txt/ nocase ascii wide
        // Description: attackers perform Active Directory collection using AdFind in batch scripts from C:\Windows\Temp\adf\ or C:\temp\ and store output in CSV files
        // Reference: http://www.joeware.net/freetools/tools/adfind/index.htm
        $string13 = /adfind\.exe\s\-gcb\s\-sc\strustdmp\s\>\s.{0,1000}\.txt/ nocase ascii wide
        // Description: attackers perform Active Directory collection using AdFind in batch scripts from C:\Windows\Temp\adf\ or C:\temp\ and store output in CSV files
        // Reference: http://www.joeware.net/freetools/tools/adfind/index.htm
        $string14 = /adfind\.exe\s\-subnets\s\-f\s\(objectCategory\=subnet\)\s\>\s.{0,1000}\.txt/ nocase ascii wide

    condition:
        any of them
}
