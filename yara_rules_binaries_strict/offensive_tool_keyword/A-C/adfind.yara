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
        $string9 = /adfind\.exe\s\-f\s\(objectcategory\=organizationalUnit\)\s\>\s.{0,100}\.txt/ nocase ascii wide
        // Description: attackers perform Active Directory collection using AdFind in batch scripts from C:\Windows\Temp\adf\ or C:\temp\ and store output in CSV files
        // Reference: http://www.joeware.net/freetools/tools/adfind/index.htm
        $string10 = /adfind\.exe\s\-f\s\(objectcategory\=person\)\s\>\s.{0,100}\.txt/ nocase ascii wide
        // Description: attackers perform Active Directory collection using AdFind in batch scripts from C:\Windows\Temp\adf\ or C:\temp\ and store output in CSV files
        // Reference: http://www.joeware.net/freetools/tools/adfind/index.htm
        $string11 = /adfind\.exe\s\-f\s.{0,100}\(objectcategory\=group\).{0,100}\s\>\s.{0,100}\.txt/ nocase ascii wide
        // Description: attackers perform Active Directory collection using AdFind in batch scripts from C:\Windows\Temp\adf\ or C:\temp\ and store output in CSV files
        // Reference: http://www.joeware.net/freetools/tools/adfind/index.htm
        $string12 = /adfind\.exe\s\-f\sobjectcategory\=computer\s\>\s.{0,100}\.txt/ nocase ascii wide
        // Description: attackers perform Active Directory collection using AdFind in batch scripts from C:\Windows\Temp\adf\ or C:\temp\ and store output in CSV files
        // Reference: http://www.joeware.net/freetools/tools/adfind/index.htm
        $string13 = /adfind\.exe\s\-gcb\s\-sc\strustdmp\s\>\s.{0,100}\.txt/ nocase ascii wide
        // Description: attackers perform Active Directory collection using AdFind in batch scripts from C:\Windows\Temp\adf\ or C:\temp\ and store output in CSV files
        // Reference: http://www.joeware.net/freetools/tools/adfind/index.htm
        $string14 = /adfind\.exe\s\-subnets\s\-f\s\(objectCategory\=subnet\)\s\>\s.{0,100}\.txt/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
